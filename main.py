"""PayGuard: scans PayPal invoices for the fake-invoice phone scam.

Run:  uvicorn main:app --reload
Pages: /check (paste an invoice), /dashboard (everything scanned so far)
"""
import asyncio
import hashlib
import html
import json
import logging
import os
import re
import sqlite3
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from urllib.parse import quote

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

import elastic_client as elastic
import notifier
import paypal_client as pp
from scorer import PHONE_RE, SCAM_THRESHOLD, normalize_phone, run_rules, score_invoice

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("payguard")

DB_PATH = os.getenv("PAYGUARD_DB", "payguard.db")
VERIFY_WEBHOOK = os.getenv("PAYPAL_VERIFY_WEBHOOK", "true").lower() == "true"
AUTO_BLOCK = os.getenv("PAYGUARD_AUTO_BLOCK", "true").lower() == "true"
INVOICE_EVENTS = {"INVOICING.INVOICE.CREATED", "INVOICING.INVOICE.UPDATED", "INVOICING.INVOICE.SCHEDULED"}
STOP_NOTE = "This invoice was stopped by PayGuard because it matches a known scam pattern."

_in_progress: set[str] = set()


# ---------- storage ----------

def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(_db()) as conn, conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                   invoice_id TEXT PRIMARY KEY, fingerprint TEXT, item_name TEXT, amount TEXT,
                   sender TEXT, verdict TEXT, risk_score INTEGER, action TEXT,
                   result TEXT, scanned_at TEXT)"""
        )
        conn.execute("CREATE TABLE IF NOT EXISTS blocklist (phone TEXT PRIMARY KEY, reported_at TEXT)")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS guardians (
                   email TEXT PRIMARY KEY, contact_name TEXT, contact_email TEXT, created_at TEXT)"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                   alert_key TEXT PRIMARY KEY, protected_email TEXT, contact_email TEXT,
                   verdict TEXT, sent INTEGER, created_at TEXT)"""
        )
        conn.execute("CREATE TABLE IF NOT EXISTS disputes (dispute_id TEXT PRIMARY KEY, status TEXT, updated_at TEXT)")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def blocked_phones() -> frozenset[str]:
    with closing(_db()) as conn:
        return frozenset(r["phone"] for r in conn.execute("SELECT phone FROM blocklist"))


def block_phones(phones: list[str]) -> None:
    with closing(_db()) as conn, conn:
        conn.executemany(
            "INSERT OR IGNORE INTO blocklist (phone, reported_at) VALUES (?, ?)",
            [(p, _now()) for p in phones if p],
        )


def get_scan(invoice_id: str):
    with closing(_db()) as conn:
        return conn.execute("SELECT * FROM scans WHERE invoice_id = ?", (invoice_id,)).fetchone()


def save_scan(invoice_id: str, fingerprint: str, fields: dict, result: dict, action: str) -> None:
    with closing(_db()) as conn, conn:
        conn.execute(
            "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?,?,?)",
            (invoice_id, fingerprint, fields["item_name"], f'{fields["amount"]} {fields["currency"]}',
             fields["sender"], result["verdict"], result["risk_score"], action,
             json.dumps(result, ensure_ascii=False), _now()),
        )


# ---------- trusted contacts ----------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def clean_email(value: str) -> str:
    value = (value or "").strip().lower()
    return value if EMAIL_RE.match(value) else ""


def get_guardian(email: str):
    with closing(_db()) as conn:
        return conn.execute("SELECT * FROM guardians WHERE email = ?", (clean_email(email),)).fetchone()


def save_guardian(email: str, contact_name: str, contact_email: str) -> None:
    with closing(_db()) as conn, conn:
        conn.execute(
            "INSERT OR REPLACE INTO guardians VALUES (?,?,?,?)",
            (email, contact_name.strip()[:80], contact_email, _now()),
        )


async def alert_guardian(recipient: str, item_name: str, amount: str, result: dict,
                         action: str, alert_key: str) -> str | None:
    """Tell the recipient's trusted contact about a risky invoice, once per invoice.

    Returns the contact's name if an alert was sent, else None.
    """
    if result["verdict"] == "SAFE":
        return None
    guardian = get_guardian(recipient)
    if not guardian:
        return None
    with closing(_db()) as conn:
        if conn.execute("SELECT 1 FROM alerts WHERE alert_key = ? AND sent = 1", (alert_key,)).fetchone():
            return None
    payload = notifier.build_alert(
        guardian["email"], guardian["contact_name"], guardian["contact_email"],
        item_name, amount, result, action,
    )
    sent = await notifier.send_alert(payload)
    with closing(_db()) as conn, conn:
        conn.execute(
            "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?)",
            (alert_key, guardian["email"], guardian["contact_email"], result["verdict"], int(sent), _now()),
        )
    return guardian["contact_name"] if sent else None


# ---------- invoice scanning ----------

def extract_fields(invoice: dict) -> dict:
    """Pull out everything the sender wrote, plus amount and sender identity."""
    detail = invoice.get("detail") or {}
    items = invoice.get("items") or []
    invoicer = invoice.get("invoicer") or {}
    recipients = invoice.get("primary_recipients") or [{}]
    recipient = ((recipients[0].get("billing_info") or {}).get("email_address") or "").lower()
    amount = (invoice.get("amount") or {}).get("value")
    if not amount:
        total = 0.0
        for it in items:
            try:
                total += float((it.get("unit_amount") or {}).get("value", 0)) * float(it.get("quantity", 1))
            except (TypeError, ValueError):
                pass
        amount = f"{total:.2f}"
    text = "\n".join(
        part for part in [
            detail.get("note", ""),
            detail.get("terms_and_conditions", ""),
            *[it.get("description", "") for it in items],
        ] if part
    )
    return {
        "item_name": ", ".join(it.get("name", "") for it in items if it.get("name")),
        "amount": amount,
        "currency": detail.get("currency_code", "USD"),
        "text": text,
        "sender": invoicer.get("business_name") or invoicer.get("email_address", ""),
        "status": invoice.get("status", ""),
        "recipient": recipient,
    }


async def stop_now(invoice_id: str) -> str:
    """Stop an invoice using its status right now, not the status from before scoring.

    Scoring takes several seconds, and the sender may press send in that time:
    a draft is deleted, a sent invoice is cancelled. Returns the action taken.
    """
    for attempt in (1, 2, 3):
        try:
            fresh = await pp.get_invoice(invoice_id)
        except pp.PayPalError as exc:
            if exc.status == 404:
                return "deleted_draft"  # already gone
            raise
        status = (fresh.get("status") or "").upper()
        if status in ("CANCELLED", "PAID", "MARKED_AS_PAID", "REFUNDED"):
            return "cancelled" if status == "CANCELLED" else "none"
        try:
            return await pp.stop_invoice(invoice_id, status, STOP_NOTE)
        except pp.PayPalError as exc:
            log.warning("stop attempt %s on %s (status %s) failed: %s", attempt, invoice_id, status, exc)
            await asyncio.sleep(2)
    return "failed"


async def scan_invoice(invoice_id: str) -> None:
    """Fetch, score, and if needed stop one invoice. Runs in the background."""
    if invoice_id in _in_progress:
        return
    _in_progress.add(invoice_id)
    try:
        invoice = await pp.get_invoice(invoice_id)
        fields = extract_fields(invoice)
        fingerprint = hashlib.sha256(
            f'{fields["item_name"]}|{fields["amount"]}|{fields["text"]}'.encode()
        ).hexdigest()

        previous = get_scan(invoice_id)
        if previous and previous["action"] in ("deleted_draft", "cancelled"):
            return  # already stopped
        if previous and previous["fingerprint"] == fingerprint:
            # Same content as last time. Only retry a stop that did not succeed.
            if AUTO_BLOCK and previous["verdict"] == "LIKELY_SCAM":
                action = await stop_now(invoice_id)
                with closing(_db()) as conn, conn:
                    conn.execute("UPDATE scans SET action = ? WHERE invoice_id = ?", (action, invoice_id))
                log.info("invoice %s retry stop -> %s", invoice_id, action)
            return

        known_bad = blocked_phones()
        action = "none"

        # Fast path: when the fixed rules alone are conclusive, stop the invoice
        # at once and let the slower Judge agent write the explanation afterwards.
        quick_score = run_rules(f'{fields["item_name"]}\n{fields["text"]}', known_bad)[0]
        if AUTO_BLOCK and quick_score >= SCAM_THRESHOLD:
            action = await stop_now(invoice_id)
            log.info("invoice %s stopped on rules alone (%s/100) -> %s", invoice_id, quick_score, action)

        result = await score_invoice(
            fields["item_name"], fields["amount"], fields["text"],
            currency=fields["currency"], sender=fields["sender"], known_bad_phones=known_bad,
        )
        if result["verdict"] == "LIKELY_SCAM":
            block_phones(result["phones"])
            await elastic.remember(fields["text"], label="scam", source="auto")
            if AUTO_BLOCK and action in ("none", "failed"):
                action = await stop_now(invoice_id)
        save_scan(invoice_id, fingerprint, fields, result, action)
        await alert_guardian(
            fields["recipient"], fields["item_name"], f'{fields["amount"]} {fields["currency"]}',
            result, action, alert_key=invoice_id,
        )
        log.info("invoice %s -> %s (%s/100, %s) action=%s",
                 invoice_id, result["verdict"], result["risk_score"], result["engine"], action)
    except pp.PayPalError as exc:
        if exc.status == 404:
            log.info("invoice %s no longer exists, skipping", invoice_id)
        else:
            log.error("scan of %s failed: %s", invoice_id, exc)
    except Exception:
        log.exception("scan of %s crashed", invoice_id)
    finally:
        _in_progress.discard(invoice_id)


# ---------- app ----------

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    if not VERIFY_WEBHOOK:
        log.warning("Webhook signature check is OFF. Use this only with the Webhooks simulator.")
    yield
    await pp.aclose()
    await elastic.aclose()


app = FastAPI(title="PayGuard", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/webhook/paypal")
async def paypal_webhook(request: Request, background: BackgroundTasks):
    raw = await request.body()
    if VERIFY_WEBHOOK and not await pp.verify_webhook_signature(request.headers, raw):
        raise HTTPException(status_code=400, detail="Invalid webhook signature")
    try:
        event = json.loads(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail="Body is not JSON")

    event_type = event.get("event_type", "")
    resource = event.get("resource") or {}

    if event_type in INVOICE_EVENTS:
        invoice = resource.get("invoice", resource)  # some payloads nest the invoice
        if invoice.get("id"):
            background.add_task(scan_invoice, invoice["id"])  # reply fast, scan after
    elif event_type.startswith("CUSTOMER.DISPUTE."):
        if resource.get("dispute_id"):
            with closing(_db()) as conn, conn:
                conn.execute(
                    "INSERT OR REPLACE INTO disputes VALUES (?,?,?)",
                    (resource["dispute_id"], resource.get("status", ""), _now()),
                )
            log.info("dispute %s -> %s", resource["dispute_id"], resource.get("status"))
    return {"status": "received"}


# ---------- pages ----------

STYLE_TEMPLATE = """
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?__FAMILIES__&family=Noto+Sans+Devanagari:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{
  --ledger:#EAF0F6; --paper:#FFFFFF; --ink:#14213D; --ink-soft:#4A5773; --rule:#C5D0DD;
  --stamp:#C8102E; --safe:#0B6E4F; --caution:#A8530A; --focus:#1D4ED8;
}
*{box-sizing:border-box}
html{font-size:112.5%}
body{margin:0;background:var(--ledger);color:var(--ink);line-height:1.55;
  font-family:__BODY__,"Noto Sans Devanagari",Verdana,sans-serif}
h1,h2,.brand,.stamp,.answer{font-family:__HEAD__,"Noto Sans Devanagari",Georgia,serif}
a{color:var(--ink)}
:focus-visible{outline:3px solid var(--focus);outline-offset:3px;border-radius:4px}

.top{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 2rem;max-width:68rem;margin:0 auto;padding:1.1rem 1.25rem}
.brand{font-weight:700;font-size:1.35rem;letter-spacing:-.01em;text-decoration:none;display:flex;align-items:center;gap:.55rem}
.brand i{width:1.5rem;height:1.5rem;border:3px solid var(--stamp);border-radius:50%;transform:rotate(-12deg);
  display:grid;place-items:center;font-style:normal;font-size:.7rem;color:var(--stamp)}
.top nav{display:flex;flex-wrap:wrap;gap:.25rem 1.4rem;margin-left:auto}
.top nav a{text-decoration:none;padding:.35rem 0;border-bottom:3px solid transparent}
.top nav a[aria-current=page]{border-bottom-color:var(--ink);font-weight:700}
.top nav a:hover{border-bottom-color:var(--rule)}

main{max-width:68rem;margin:0 auto;padding:1rem 1.25rem 4rem}
.narrow{max-width:38rem}
h1{font-size:clamp(2rem,4.6vw,3.1rem);line-height:1.1;letter-spacing:-.015em;font-weight:700;margin:.6rem 0 1rem;max-width:18ch}
h2{font-size:1.25rem;margin:2rem 0 .6rem}
.lede{font-size:1.15rem;color:var(--ink-soft);max-width:34rem;margin:0 0 1.8rem}

.split{display:grid;gap:2.5rem 3.5rem;grid-template-columns:minmax(0,1.15fr) minmax(0,.85fr);align-items:start}
@media (max-width:52rem){.split{grid-template-columns:1fr}}

label{display:block;font-weight:700;margin:1.2rem 0 .3rem}
.hint{display:block;font-weight:400;color:var(--ink-soft);font-size:.92rem}
input,textarea,select{width:100%;font:inherit;color:inherit;background:var(--paper);
  border:2px solid var(--ink);border-radius:6px;padding:.75rem .85rem}
textarea{min-height:8.5rem;resize:vertical}
.row{display:grid;grid-template-columns:2fr 1fr;gap:0 1rem}
@media (max-width:30rem){.row{grid-template-columns:1fr}}

.btn{display:inline-block;font:inherit;font-weight:700;text-decoration:none;cursor:pointer;
  min-height:3.4rem;padding:.9rem 1.5rem;border-radius:6px;border:2px solid var(--ink);
  background:var(--ink);color:#fff;margin:.4rem .5rem 0 0}
.btn:hover{background:#0B1530}
.btn.quiet{background:transparent;color:var(--ink)}
.btn.quiet:hover{background:var(--paper)}
.btn.alarm{background:var(--stamp);border-color:var(--stamp)}
.btn[disabled]{opacity:.7;cursor:progress}
.go{margin-top:1.6rem}
form.inline{display:inline}

/* the invoice slip: the page's one piece of theatre */
.slip{position:relative;background:var(--paper);border:1px solid var(--rule);border-radius:3px;
  padding:1.5rem 1.5rem 1.7rem;box-shadow:0 1px 0 var(--rule),0 14px 30px -18px rgba(20,33,61,.45)}
.slip::before{content:"";position:absolute;left:0;right:0;top:-7px;height:7px;
  background:radial-gradient(circle at 7px 7px,var(--paper) 6px,transparent 6.5px) 0 0/14px 7px repeat-x}
.slip dl{display:grid;grid-template-columns:auto 1fr;gap:.35rem 1.2rem;margin:0 0 1rem;padding-bottom:1rem;border-bottom:1px dashed var(--rule)}
.slip dt{color:var(--ink-soft)}
.slip dd{margin:0;font-weight:700;overflow-wrap:anywhere}
.slip p{margin:0;overflow-wrap:anywhere}
.slip p.note{white-space:pre-wrap}
.slip.judged{padding-bottom:5.2rem}
.slip-title{font-size:.92rem;color:var(--ink-soft);margin:0 0 .8rem}
.flag{background:none;color:var(--stamp);font-weight:700;text-decoration:underline wavy var(--stamp);text-underline-offset:4px}
.flag.struck{text-decoration:line-through 3px var(--stamp);white-space:nowrap}
.notes{list-style:none;padding:0;margin:1.3rem 0 0;font-size:.95rem;color:var(--ink-soft)}
.notes li{padding-left:1.5rem;position:relative;margin:.45rem 0}
.notes li::before{content:"";position:absolute;left:0;top:.75em;width:1rem;border-top:2px solid var(--stamp)}

.stamp{position:absolute;right:1.2rem;bottom:1.1rem;transform:rotate(-9deg);
  font-weight:700;font-size:clamp(1.1rem,3.4vw,1.6rem);text-transform:uppercase;letter-spacing:.06em;line-height:1.1;
  padding:.5rem .9rem;border:4px solid currentColor;border-radius:8px;outline:2px solid currentColor;outline-offset:3px;
  background:rgba(255,255,255,.82);mix-blend-mode:multiply;text-align:center;max-width:80%}
.stamp.scam{color:var(--stamp)}.stamp.caution{color:var(--caution)}.stamp.safe{color:var(--safe)}
@media (prefers-reduced-motion:no-preference){
  .stamp{animation:thunk .42s cubic-bezier(.2,1.4,.4,1) .25s both}
  @keyframes thunk{from{opacity:0;transform:rotate(-2deg) scale(2.3)}to{opacity:1;transform:rotate(-9deg) scale(1)}}
}

.answer{font-size:1.3rem;line-height:1.45;margin:0 0 1.2rem;max-width:32rem}
.meter{height:.7rem;background:var(--paper);border:1px solid var(--rule);border-radius:99px;overflow:hidden;max-width:22rem}
.meter b{display:block;height:100%}
.meter-label{font-size:.95rem;color:var(--ink-soft);margin:.4rem 0 0}
.why{padding-left:1.2rem;margin:.4rem 0 0;max-width:36rem}
.why li{margin:.45rem 0}
.told{background:var(--paper);border-left:6px solid var(--safe);padding:1rem 1.2rem;margin:1.6rem 0 0;max-width:36rem;border-radius:0 6px 6px 0}
.actions{margin-top:1.8rem}

.sum{font-size:1.3rem;max-width:38rem;margin:0 0 2rem}
.sum b{font-size:1.15em}
.tablewrap{overflow-x:auto;background:var(--paper);border:1px solid var(--rule);border-radius:6px}
table{border-collapse:collapse;width:100%;min-width:40rem;font-size:.95rem}
th{text-align:left;font-weight:700;color:var(--ink-soft);padding:.8rem 1rem;border-bottom:2px solid var(--ink)}
td{padding:.85rem 1rem;border-bottom:1px solid var(--rule);vertical-align:top}
tr:last-child td{border-bottom:0}
td small{display:block;color:var(--ink-soft);font-size:.8rem}
.chip{display:inline-block;font-weight:700;padding:.1rem .6rem;border:2px solid currentColor;border-radius:5px;white-space:nowrap}
.chip.scam{color:var(--stamp)}.chip.caution{color:var(--caution)}.chip.safe{color:var(--safe)}
.empty{padding:2rem 1.2rem;color:var(--ink-soft)}
footer{max-width:68rem;margin:0 auto;padding:1.5rem 1.25rem 3rem;color:var(--ink-soft);font-size:.88rem;border-top:1px solid var(--rule)}
</style>"""

# Typeface presets. Change the look with PAYGUARD_FONT in .env: serif (default), lexend, grotesk, plain.
FONT_PRESETS = {
    "serif": ("family=Fraunces:opsz,wght@9..144,600;9..144,700&family=Lexend:wght@400;700", '"Fraunces"', '"Lexend"'),
    "lexend": ("family=Lexend:wght@400;700", '"Lexend"', '"Lexend"'),
    "grotesk": ("family=Bricolage+Grotesque:opsz,wght@12..96,700&family=Atkinson+Hyperlegible:wght@400;700",
                '"Bricolage Grotesque"', '"Atkinson Hyperlegible"'),
    "plain": ("family=Atkinson+Hyperlegible:wght@400;700", '"Atkinson Hyperlegible"', '"Atkinson Hyperlegible"'),
}
_families, _head, _body = FONT_PRESETS.get(os.getenv("PAYGUARD_FONT", "serif").lower(), FONT_PRESETS["serif"])
STYLE = STYLE_TEMPLATE.replace("__FAMILIES__", _families).replace("__HEAD__", _head).replace("__BODY__", _body)

TONE = {"SAFE": "safe", "SUSPICIOUS": "caution", "LIKELY_SCAM": "scam"}
TONE_COLOR = {"safe": "var(--safe)", "caution": "var(--caution)", "scam": "var(--stamp)"}
LABELS = {"SAFE": "Looks safe", "SUSPICIOUS": "Be careful", "LIKELY_SCAM": "Likely a scam"}
ACTION_WORDS = {
    "deleted_draft": "Stopped before it was sent",
    "cancelled": "Cancelled after it was sent",
    "none": "Left alone",
    "failed": "Could not be stopped",
}
TEXT = {
    "en": {
        "stamp": LABELS,
        "slip": "The invoice you checked", "for": "For", "amount": "Amount",
        "risk": "Risk {n} out of 100", "why": "Why we think so",
        "told": "We have told <b>{name}</b>, your trusted person, about this invoice. "
                "Wait for their call before you do anything.",
        "report": "Report this scam", "ask": "Ask someone I trust", "again": "Check another invoice",
    },
    "hi": {
        "stamp": {"SAFE": "सुरक्षित लगता है", "SUSPICIOUS": "सावधान रहें", "LIKELY_SCAM": "घोटाला लगता है"},
        "slip": "आपने जो इनवॉइस जाँचा", "for": "किसके लिए", "amount": "राशि",
        "risk": "जोखिम 100 में से {n}", "why": "हमें ऐसा क्यों लगता है",
        "told": "हमने आपके भरोसेमंद व्यक्ति <b>{name}</b> को इस इनवॉइस के बारे में बता दिया है। "
                "कुछ भी करने से पहले उनके कॉल का इंतज़ार करें।",
        "report": "इस घोटाले की रिपोर्ट करें", "ask": "किसी भरोसेमंद से पूछें", "again": "दूसरा इनवॉइस जाँचें",
    },
}
NAV = [("/check", "Check an invoice"), ("/protect", "Trusted person"), ("/dashboard", "Activity")]


def _page(title: str, body: str, current: str = "", lang: str = "en") -> HTMLResponse:
    nav = "".join(
        f'<a href="{href}"{" aria-current=page" if href == current else ""}>{label}</a>' for href, label in NAV
    )
    return HTMLResponse(
        f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><title>{html.escape(title)}</title>{STYLE}</head>'
        f'<body><header class="top"><a class="brand" href="/check"><i>✓</i>PayGuard</a><nav>{nav}</nav></header>'
        f"<main>{body}</main>"
        "<footer>A prototype running on the PayPal sandbox. No real money moves here.</footer></body></html>"
    )


def _mark_phones(text: str, struck: bool) -> str:
    """Escape invoice text and underline (or strike through) any phone numbers in it."""
    out, last = [], 0
    for m in PHONE_RE.finditer(text):
        out.append(html.escape(text[last:m.start()]))
        out.append(f'<mark class="flag{" struck" if struck else ""}">{html.escape(m.group())}</mark>')
        last = m.end()
    out.append(html.escape(text[last:]))
    return "".join(out)


@app.get("/")
async def home():
    return RedirectResponse("/check")


@app.get("/check", response_class=HTMLResponse)
async def check_form():
    return _page("PayGuard: check an invoice", """
    <div class="split">
      <section>
        <h1>Got an invoice you weren't expecting? Check it before you call.</h1>
        <p class="lede">Scammers send real PayPal invoices with a phone number to call. Paste yours here
        and get a plain answer in a few seconds.</p>
        <form method="post" action="/check" id="checkform">
          <div class="row">
            <div><label for="item">What does it say it is for?</label>
              <input id="item" name="item_name" placeholder="Antivirus renewal" required maxlength="200"></div>
            <div><label for="amount">How much?</label>
              <input id="amount" name="amount" placeholder="600" required maxlength="20" inputmode="decimal"></div>
          </div>
          <label for="note">The message written on the invoice
            <span class="hint">Copy the note or description exactly as it appears.</span></label>
          <textarea id="note" name="note" required maxlength="5000"></textarea>
          <div class="row">
            <div><label for="email">Your email, if you like
              <span class="hint">If you set up a trusted person, we tell them for you.</span></label>
              <input id="email" name="email" type="email" placeholder="you@example.com" maxlength="200"></div>
            <div><label for="language">Answer in<span class="hint">&nbsp;</span></label>
              <select id="language" name="language"><option value="en">English</option><option value="hi">हिन्दी</option></select></div>
          </div>
          <div class="go"><button class="btn" id="go" type="submit">Check this invoice</button></div>
        </form>
      </section>
      <aside aria-label="What a scam invoice looks like">
        <div class="slip">
          <p class="slip-title">What these invoices usually look like</p>
          <dl><dt>For</dt><dd>Security plan renewal</dd><dt>Amount</dt><dd>$600.00</dd></dl>
          <p>Your account <mark class="flag">will be charged within 24 hours</mark>. To cancel,
          <mark class="flag">call 1-800-555-0199</mark>.</p>
        </div>
        <ul class="notes">
          <li>An invoice is only paid if you choose to pay it. Nothing is charged automatically.</li>
          <li>PayPal never asks you to phone a number written inside an invoice.</li>
          <li>The number belongs to the scammer, who will ask for codes, payments or access to your computer.</li>
        </ul>
      </aside>
    </div>
    <script>
      document.getElementById("checkform").addEventListener("submit", function () {
        var b = document.getElementById("go"); b.disabled = true; b.textContent = "Checking, this takes a few seconds";
      });
    </script>""", current="/check")


@app.post("/check", response_class=HTMLResponse)
async def check_submit(
    item_name: str = Form(..., max_length=200),
    amount: str = Form(..., max_length=20),
    note: str = Form(..., max_length=5000),
    language: str = Form("en"),
    email: str = Form("", max_length=200),
):
    lang = language if language in TEXT else "en"
    t = TEXT[lang]
    result = await score_invoice(item_name, amount, note, known_bad_phones=blocked_phones(), language=lang)
    verdict = result["verdict"]
    tone = TONE[verdict]
    alert_key = "check:" + hashlib.sha256(f"{clean_email(email)}|{note}".encode()).hexdigest()
    told = await alert_guardian(email, item_name, amount, result, "checked", alert_key)

    told_html = f'<p class="told">{t["told"].format(name=html.escape(told))}</p>' if told else ""
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in result["reasons"])
    share = quote(f"I got this invoice and PayGuard says: {LABELS[verdict]}.\n\n{item_name} - {amount}\n\n{note}\n\nCan you take a look?")
    report = (
        f'<form class="inline" method="post" action="/report">'
        f'<input type="hidden" name="phones" value="{html.escape(",".join(result["phones"]))}">'
        f'<input type="hidden" name="note" value="{html.escape(note)}">'
        f'<button class="btn alarm">{t["report"]}</button></form>'
        if verdict != "SAFE" else ""
    )
    return _page("PayGuard: " + LABELS[verdict], f"""
    <div class="split">
      <section>
        <div class="slip judged">
          <div class="stamp {tone}" role="status">{t["stamp"][verdict]}</div>
          <p class="slip-title">{t["slip"]}</p>
          <dl><dt>{t["for"]}</dt><dd>{html.escape(item_name)}</dd><dt>{t["amount"]}</dt><dd>{html.escape(amount)}</dd></dl>
          <p class="note">{_mark_phones(note, struck=verdict != "SAFE")}</p>
        </div>
      </section>
      <section>
        <p class="answer">{html.escape(result["plain_explanation"])}</p>
        <div class="meter" aria-hidden="true"><b style="width:{result["risk_score"]}%;background:{TONE_COLOR[tone]}"></b></div>
        <p class="meter-label">{t["risk"].format(n=result["risk_score"])}</p>
        {told_html}
        {f'<h2>{t["why"]}</h2><ul class="why">{reasons}</ul>' if reasons else ""}
        <div class="actions">
          {report}
          <a class="btn quiet" href="mailto:?subject={quote("Is this invoice a scam?")}&body={share}">{t["ask"]}</a>
          <a class="btn quiet" href="/check">{t["again"]}</a>
        </div>
      </section>
    </div>""", lang=lang)


@app.get("/protect", response_class=HTMLResponse)
async def protect_form():
    return _page("PayGuard: trusted person", """
    <div class="narrow">
      <h1>Choose someone to stand beside you.</h1>
      <p class="lede">Pick a person you trust, like a son, daughter or friend. If a risky invoice is sent
      to your PayPal email, we email them straight away, so you never have to decide alone.</p>
      <form method="post" action="/protect">
        <label for="email">Your PayPal email</label>
        <input id="email" name="email" type="email" required maxlength="200">
        <label for="cname">Their name</label>
        <input id="cname" name="contact_name" required maxlength="80">
        <label for="cemail">Their email</label>
        <input id="cemail" name="contact_email" type="email" required maxlength="200">
        <div class="go"><button class="btn" type="submit">Save trusted person</button></div>
      </form>
    </div>""", current="/protect")


@app.post("/protect", response_class=HTMLResponse)
async def protect_submit(
    email: str = Form(..., max_length=200),
    contact_name: str = Form(..., max_length=80),
    contact_email: str = Form(..., max_length=200),
):
    email, contact_email = clean_email(email), clean_email(contact_email)
    if not email or not contact_email or not contact_name.strip():
        return _page("PayGuard: check the details", """
        <div class="narrow"><h1>Those details did not go through.</h1>
        <p class="lede">We need two valid email addresses and a name. Nothing was saved.</p>
        <a class="btn" href="/protect">Try again</a></div>""", current="/protect")
    save_guardian(email, contact_name, contact_email)
    return _page("PayGuard: trusted person saved", f"""
    <div class="narrow"><h1>Trusted person saved.</h1>
    <p class="lede"><b>{html.escape(contact_name.strip())}</b> will get an email if a risky invoice is sent to
    <b>{html.escape(email)}</b>. Ask them to add payguard alerts to their contacts so the email is not filtered.</p>
    <a class="btn" href="/check">Check an invoice</a></div>""", current="/protect")


@app.post("/report", response_class=HTMLResponse)
async def report(phones: str = Form(""), note: str = Form("", max_length=5000)):
    numbers = [normalize_phone(p) for p in phones.split(",") if p.strip()]
    block_phones(numbers)
    await elastic.remember(note, label="scam", source="report")
    count = f"{len(numbers)} phone number" + ("" if len(numbers) == 1 else "s")
    return _page("PayGuard: reported", f"""
    <div class="narrow"><h1>Reported. Thank you.</h1>
    <p class="lede">This invoice and {count} are now in the shared scam memory. The next person who
    receives something similar is warned straight away.</p>
    <a class="btn" href="/check">Check another invoice</a></div>""")


def _plural(n: int, one: str, many: str = "") -> str:
    return one if n == 1 else (many or one + "s")


def _when(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d %b, %H:%M UTC").lstrip("0")
    except ValueError:
        return iso


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    with closing(_db()) as conn:
        scans = conn.execute("SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 100").fetchall()
        n_blocked = conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0]
        n_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE sent = 1").fetchone()[0]
        n_guardians = conn.execute("SELECT COUNT(*) FROM guardians").fetchone()[0]
    stopped = sum(1 for s in scans if s["action"] in ("deleted_draft", "cancelled"))
    rows = "".join(
        f"<tr><td>{html.escape(s['item_name'] or 'Untitled')}<small>{html.escape(s['invoice_id'])}</small></td>"
        f"<td>{html.escape(s['amount'] or '')}</td>"
        f"<td><span class='chip {TONE.get(s['verdict'], 'caution')}'>{LABELS.get(s['verdict'], html.escape(s['verdict']))}</span>"
        f"<small>Risk {s['risk_score']} out of 100</small></td>"
        f"<td>{ACTION_WORDS.get(s['action'], html.escape(s['action']))}</td>"
        f"<td>{html.escape(_when(s['scanned_at']))}</td></tr>"
        for s in scans
    )
    table = (
        f"<div class='tablewrap'><table><thead><tr><th>Invoice</th><th>Amount</th><th>Result</th>"
        f"<th>What PayGuard did</th><th>When</th></tr></thead><tbody>{rows}</tbody></table></div>"
        if scans else
        "<div class='tablewrap'><p class='empty'>No invoices have come in from PayPal yet. Invoices created "
        "by the connected account appear here within seconds.</p></div>"
    )
    return _page("PayGuard: activity", f"""
    <h1>Every invoice is read before it leaves.</h1>
    <p class="sum"><b>{len(scans)}</b> scanned and <b>{stopped}</b> stopped.
    <b>{n_alerts}</b> {_plural(n_alerts, "alert")} sent to trusted people,
    <b>{n_guardians}</b> {_plural(n_guardians, "person", "people")} protected,
    <b>{n_blocked}</b> scam phone {_plural(n_blocked, "number")} on the shared list.</p>
    {table}""", current="/dashboard")


@app.get("/api/scans")
async def api_scans():
    with closing(_db()) as conn:
        return [dict(r) | {"result": json.loads(r["result"])} for r in conn.execute("SELECT * FROM scans ORDER BY scanned_at DESC")]