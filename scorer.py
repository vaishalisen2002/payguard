"""PayGuard scoring: fixed rules + Elastic scam memory + the Elastic Judge agent.

Works without Elastic too (rules only), so the demo never breaks.
"""
import logging
import re

import elastic_client as elastic

log = logging.getLogger("payguard.scorer")

SCAM_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 30

PHONE_RE = re.compile(
    r"(?<![\w.])(?:\+?\d{1,3}[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}|\d{5}[\s\-]?\d{5})(?!\d)"
)

# (flag name, weight, pattern, reason shown to the user)
RULES = [
    (
        "call_to_cancel",
        20,
        re.compile(
            r"\b(call|contact|dial|phone|reach)\b.{0,60}\b(cancel|refund|dispute|stop|reverse|unauthori[sz]ed)"
            r"|\b(cancel|refund|dispute|stop|reverse|unauthori[sz]ed)\w*\b.{0,60}\b(call|contact|dial|phone|reach)\b",
            re.I | re.S,
        ),
        "It tells you to call a number to cancel or get a refund. PayPal never asks for that.",
    ),
    (
        "auto_charge_urgency",
        25,
        re.compile(
            r"(within|in)\s+\d+\s*(hours?|hrs?|days?)|will be (auto[\s\-]?)?(charged|debited|deducted|renewed)"
            r"|auto[\s\-]?(renew|debit)|immediately|act now|avoid (the )?charge",
            re.I,
        ),
        "It says you will be charged automatically or sets a short deadline. An invoice is only paid if you choose to pay it.",
    ),
    (
        "remote_access",
        30,
        re.compile(r"anydesk|teamviewer|ultraviewer|quick\s?assist|remote (access|desktop|support)|screen ?shar", re.I),
        "It mentions remote-access software, a common way scammers take over a device.",
    ),
    (
        "untraceable_payment",
        30,
        re.compile(r"gift ?cards?|bitcoin|crypto|wire transfer|western union|zelle", re.I),
        "It asks for gift cards, crypto or a wire transfer, which cannot be reversed.",
    ),
    (
        "brand_name",
        15,
        re.compile(r"\b(norton|mcafee|geek ?squad|best ?buy|microsoft|windows defender|apple|amazon|coinbase|binance)\b", re.I),
        "It uses a well-known brand name. Real brands do not bill strangers through personal invoices.",
    ),
    (
        "fake_support",
        15,
        re.compile(r"paypal.{0,20}(support|help ?desk|security|team|billing)|(help ?desk|fraud department|billing department)", re.I),
        "It poses as a support or security team inside the invoice text.",
    ),
]
PHONE_WEIGHT = 25
BLOCKLIST_WEIGHT = 60
MEMORY_WEIGHT = 20  # most of the similar remembered cases are scams

FALLBACK_TEXT = {
    "en": {
        "LIKELY_SCAM": "This looks like a scam. Do not call any number in it and do not pay. PayPal will never charge you automatically for an invoice.",
        "SUSPICIOUS": "Something about this invoice is unusual. Do not call numbers in it. If you did not order this, ignore it or report it.",
        "SAFE": "Nothing suspicious was found. Still, only pay invoices for things you actually ordered.",
    },
    "hi": {
        "LIKELY_SCAM": "यह धोखाधड़ी लगती है। इसमें दिए किसी नंबर पर कॉल न करें और भुगतान न करें। PayPal किसी इनवॉइस का पैसा अपने आप नहीं काटता।",
        "SUSPICIOUS": "इस इनवॉइस में कुछ असामान्य है। इसमें दिए नंबर पर कॉल न करें। अगर आपने यह ऑर्डर नहीं किया, तो इसे अनदेखा करें या रिपोर्ट करें।",
        "SAFE": "कुछ संदिग्ध नहीं मिला। फिर भी, केवल उन्हीं इनवॉइस का भुगतान करें जो आपने सच में ऑर्डर किए हों।",
    },
}


def normalize_phone(raw: str) -> str:
    """Digits only, without a leading country '1', so formats compare equal."""
    digits = re.sub(r"\D", "", raw)
    return digits[1:] if len(digits) == 11 and digits.startswith("1") else digits


def extract_phones(text: str) -> list[str]:
    seen, out = set(), []
    for m in PHONE_RE.finditer(text or ""):
        n = normalize_phone(m.group())
        if len(n) >= 10 and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def verdict_for(score: int) -> str:
    if score >= SCAM_THRESHOLD:
        return "LIKELY_SCAM"
    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "SAFE"


def run_rules(text: str, known_bad_phones=frozenset()) -> tuple[int, list[str], list[str], list[str]]:
    """Return (score, flag names, reasons, phone numbers found)."""
    text = text or ""
    score, flags, reasons = 0, [], []
    phones = extract_phones(text)

    if any(p in known_bad_phones for p in phones):
        score += BLOCKLIST_WEIGHT
        flags.append("reported_number")
        reasons.append("The phone number in it was already reported as a scam by another user.")
    if phones:
        score += PHONE_WEIGHT
        flags.append("phone_number")
        reasons.append("It contains a phone number. Scam invoices use one to get you on a call.")
    for name, weight, pattern, reason in RULES:
        if pattern.search(text):
            score += weight
            flags.append(name)
            reasons.append(reason)
    return min(score, 100), flags, reasons, phones


async def score_invoice(
    item_name: str,
    amount: str,
    text: str,
    *,
    currency: str = "USD",
    sender: str = "",
    known_bad_phones=frozenset(),
    language: str = "en",
) -> dict:
    """Score one invoice.

    `text` is everything the sender wrote: note, terms, item descriptions.
    Final score = the higher of the evidence score (rules + memory) and the
    evidence/Judge average, so hard evidence is never talked down, and a
    Judge hunch alone can make an invoice SUSPICIOUS but not auto-blocked.
    """
    language = language if language in FALLBACK_TEXT else "en"
    combined_text = f"{item_name}\n{text}"
    rule_score, flags, rule_reasons, phones = run_rules(combined_text, known_bad_phones)

    # Pattern agent: look for similar cases in the Elastic scam memory.
    cases = await elastic.similar_cases(text)
    scam_matches = sum(1 for c in cases if c["label"] == "scam")
    if cases and scam_matches * 2 > len(cases):
        rule_score = min(100, rule_score + MEMORY_WEIGHT)
        flags.append("similar_to_known_scams")
        rule_reasons.append(f"It closely resembles {scam_matches} invoices already reported as scams.")

    # Judge agent: Elastic Agent Builder weighs all the evidence.
    judge = await elastic.ask_judge(
        {"sender": sender, "item": item_name, "amount": f"{amount} {currency}", "sender_text": (text or "")[:4000]},
        flags,
        [{"label": c["label"], "content": c["content"][:300]} for c in cases],
        language,
    )

    if judge:
        score = max(rule_score, round((rule_score + judge["risk_score"]) / 2))
        engine = "rules+memory+judge"
    else:
        score = rule_score
        engine = "rules+memory" if cases else "rules-only"
    verdict = verdict_for(score)

    if judge and language == "hi":
        reasons = judge["reasons"] or rule_reasons
    else:
        reasons = rule_reasons + [r for r in (judge["reasons"] if judge else []) if r not in rule_reasons]

    return {
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons[:5],
        "plain_explanation": (judge or {}).get("plain_explanation") or FALLBACK_TEXT[language][verdict],
        "rule_flags": flags,
        "rule_score": rule_score,
        "judge_score": judge["risk_score"] if judge else None,
        "similar_scams": scam_matches,
        "phones": phones,
        "engine": engine,
    }