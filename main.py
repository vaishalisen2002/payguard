"""PayGuard: scans PayPal invoices for the fake-invoice phone scam.

Run:  uvicorn main:app --reload
Pages: /check (paste an invoice), /dashboard (everything scanned so far)
"""
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
from scorer import normalize_phone, score_invoice

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
        if previous and (previous["fingerprint"] == fingerprint or previous["action"] != "none"):
            return  # same content already scanned, or already stopped

        result = await score_invoice(
            fields["item_name"], fields["amount"], fields["text"],
            currency=fields["currency"], sender=fields["sender"], known_bad_phones=blocked_phones(),
        )
        action = "none"
        if result["verdict"] == "LIKELY_SCAM":
            block_phones(result["phones"])
            await elastic.remember(fields["text"], label="scam", source="auto")
            if AUTO_BLOCK:
                action = await pp.stop_invoice(invoice_id, fields["status"], STOP_NOTE)
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

COLORS = {"SAFE": "#1a7f37", "SUSPICIOUS": "#b35900", "LIKELY_SCAM": "#c62828"}
LABELS = {"SAFE": "Looks safe", "SUSPICIOUS": "Be careful", "LIKELY_SCAM": "Likely a scam"}
STYLE = """<meta name="viewport" content="width=device-width, initial-scale=1"><style>
body{font-family:system-ui,sans-serif;max-width:680px;margin:40px auto;padding:0 16px;font-size:18px;color:#1c1c1c}
input,textarea,select{width:100%;padding:12px;font-size:18px;margin:6px 0 16px;box-sizing:border-box;border:1px solid #999;border-radius:8px}
button,.btn{display:inline-block;padding:14px 22px;font-size:18px;border:0;border-radius:8px;background:#003087;color:#fff;cursor:pointer;text-decoration:none;margin:6px 6px 0 0}
.btn.grey{background:#555}.verdict{color:#fff;padding:20px;border-radius:12px;font-size:26px;font-weight:700}
table{border-collapse:collapse;width:100%;font-size:15px}td,th{border-bottom:1px solid #ddd;padding:8px;text-align:left}
</style>"""


def _page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><html><head><title>{html.escape(title)}</title>{STYLE}</head><body>{body}</body></html>")


@app.get("/")
async def home():
    return RedirectResponse("/check")


@app.get("/check", response_class=HTMLResponse)
async def check_form():
    return _page("PayGuard", """
    <h1>PayGuard</h1><p>Got an invoice you did not expect? Check it before you call or pay.</p>
    <form method="post" action="/check">
      <label>What is it for?</label><input name="item_name" placeholder="e.g. Antivirus renewal" required>
      <label>Amount</label><input name="amount" placeholder="600" required>
      <label>Paste the message from the invoice</label><textarea name="note" rows="6" required></textarea>
      <label>Your email (optional). If you set up a trusted person, we will tell them for you.</label>
      <input name="email" type="email" placeholder="you@example.com">
      <label>Language</label><select name="language"><option value="en">English</option><option value="hi">हिन्दी</option></select>
      <button type="submit">Check this invoice</button>
    </form><p><a href="/protect">Set up a trusted person</a> &middot; <a href="/dashboard">Dashboard</a></p>""")


@app.post("/check", response_class=HTMLResponse)
async def check_submit(
    item_name: str = Form(..., max_length=200),
    amount: str = Form(..., max_length=20),
    note: str = Form(..., max_length=5000),
    language: str = Form("en"),
    email: str = Form("", max_length=200),
):
    result = await score_invoice(item_name, amount, note, known_bad_phones=blocked_phones(), language=language)
    verdict = result["verdict"]
    alert_key = "check:" + hashlib.sha256(f"{clean_email(email)}|{note}".encode()).hexdigest()
    told = await alert_guardian(email, item_name, amount, result, "checked", alert_key)
    told_html = (
        f'<p style="background:#e8f0fe;padding:14px;border-radius:8px">We have told <b>{html.escape(told)}</b>, '
        f'your trusted person, about this invoice. Wait for their call before you do anything.</p>'
        if told else ""
    )
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in result["reasons"])
    phones = ",".join(result["phones"])
    share = quote(f"I got this invoice and PayGuard says: {LABELS[verdict]}.\n\n{item_name} - {amount}\n\n{note}\n\nCan you take a look?")
    report = (
        f'<form method="post" action="/report" style="display:inline">'
        f'<input type="hidden" name="phones" value="{html.escape(phones)}">'
        f'<input type="hidden" name="note" value="{html.escape(note)}"><button>Report this scam</button></form>'
        if verdict != "SAFE" else ""
    )
    return _page("PayGuard result", f"""
    <div class="verdict" style="background:{COLORS[verdict]}">{LABELS[verdict]} &middot; risk {result['risk_score']}/100</div>
    <p>{html.escape(result['plain_explanation'])}</p><ul>{reasons}</ul>
    {told_html}
    {report}
    <a class="btn grey" href="mailto:?subject={quote('Is this invoice a scam?')}&body={share}">Ask someone I trust</a>
    <a class="btn grey" href="/check">Check another</a>""")


@app.get("/protect", response_class=HTMLResponse)
async def protect_form():
    return _page("Trusted person", """
    <h1>Set up a trusted person</h1>
    <p>Pick someone you trust, like a son, daughter or friend. If a risky invoice is sent to your
    PayPal email, PayGuard tells them straight away, so you never have to decide alone.</p>
    <form method="post" action="/protect">
      <label>Your PayPal email</label><input name="email" type="email" required>
      <label>Trusted person's name</label><input name="contact_name" required maxlength="80">
      <label>Trusted person's email</label><input name="contact_email" type="email" required>
      <button type="submit">Save</button>
    </form><p><a href="/check">Back</a></p>""")


@app.post("/protect", response_class=HTMLResponse)
async def protect_submit(
    email: str = Form(..., max_length=200),
    contact_name: str = Form(..., max_length=80),
    contact_email: str = Form(..., max_length=200),
):
    email, contact_email = clean_email(email), clean_email(contact_email)
    if not email or not contact_email or not contact_name.strip():
        raise HTTPException(status_code=400, detail="Please enter two valid email addresses and a name.")
    save_guardian(email, contact_name, contact_email)
    return _page("Saved", f"""
    <h1>You are protected</h1>
    <p><b>{html.escape(contact_name.strip())}</b> will be told if a risky invoice is sent to
    <b>{html.escape(email)}</b>.</p><a class="btn" href="/check">Check an invoice</a>""")


@app.post("/report", response_class=HTMLResponse)
async def report(phones: str = Form(""), note: str = Form("", max_length=5000)):
    numbers = [normalize_phone(p) for p in phones.split(",") if p.strip()]
    block_phones(numbers)
    await elastic.remember(note, label="scam", source="report")
    return _page("Reported", f"""
    <h1>Thank you</h1><p>Reported. This invoice and {len(numbers)} phone number(s) were added to the shared scam memory,
    so the next person who gets a similar invoice is warned straight away.</p>
    <a class="btn" href="/check">Back</a>""")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    with closing(_db()) as conn:
        scans = conn.execute("SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 100").fetchall()
        n_blocked = conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0]
        n_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE sent = 1").fetchone()[0]
        n_guardians = conn.execute("SELECT COUNT(*) FROM guardians").fetchone()[0]
    rows = "".join(
        f"<tr><td>{html.escape(s['invoice_id'])}</td><td>{html.escape(s['item_name'] or '')}</td>"
        f"<td>{html.escape(s['amount'] or '')}</td>"
        f"<td style='color:{COLORS.get(s['verdict'], '#000')};font-weight:700'>{html.escape(s['verdict'])}</td>"
        f"<td>{s['risk_score']}</td><td>{html.escape(s['action'])}</td><td>{html.escape(s['scanned_at'])}</td></tr>"
        for s in scans
    ) or "<tr><td colspan=7>No invoices scanned yet.</td></tr>"
    return _page("PayGuard dashboard", f"""
    <h1>PayGuard dashboard</h1><p>{len(scans)} invoices scanned &middot; {n_blocked} reported phone numbers
    &middot; {n_guardians} people with a trusted contact &middot; {n_alerts} alerts sent</p>
    <table><tr><th>Invoice</th><th>Item</th><th>Amount</th><th>Verdict</th><th>Risk</th><th>Action</th><th>Scanned (UTC)</th></tr>{rows}</table>
    <p><a href="/check">Check an invoice</a></p>""")


@app.get("/api/scans")
async def api_scans():
    with closing(_db()) as conn:
        return [dict(r) | {"result": json.loads(r["result"])} for r in conn.execute("SELECT * FROM scans ORDER BY scanned_at DESC")]