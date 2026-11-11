"""One-time setup: create the scam memory, load examples, create the Judge agent.

Usage:  python setup_elastic.py
"""
import asyncio

import elastic_client as ec

SCAMS = [
    "Your subscription will be charged within 24 hours. To cancel, call 1-800-555-0199.",
    "Your antivirus plan has been auto-renewed for $499.99. If you did not authorize this, call our billing desk at 1-888-555-0142 immediately.",
    "Thank you for your purchase of Bitcoin worth $750. If this was not you, contact the PayPal fraud department on +1 (805) 555-0117 within 12 hours.",
    "Your account will be debited $389.00 today for a 3-year device protection plan. To dispute or get a refund call 1 833 555 0176.",
    "We noticed unauthorized activity. $600 will be deducted from your account. Call the help desk at 1-844-555-0153 to stop this transaction.",
    "Tech support annual plan renewed. Amount $349.99 will be charged in 24 hrs. For cancellation and refund call toll free 1-877-555-0190.",
    "Your order of a gaming laptop for $1,299 is confirmed. Did not place this order? Reach our support team at 1-866-555-0128 right away.",
    "PayPal Security: suspicious login detected. To secure your funds, call 1-800-555-0164 and our agent will guide you through AnyDesk.",
    "Renewal invoice for cloud storage premium, $279. You will be auto-debited today. To cancel your membership dial 1-855-555-0135.",
    "Final notice: your computer security subscription expires today and $459 will be charged. Call 1-888-555-0181 to cancel and receive a refund.",
    "Refund pending. We overcharged you $500. Call 1-800-555-0109 and purchase gift cards so we can reverse the transaction.",
    "Your crypto wallet purchase of $980 was successful. If you do not recognise it, phone the billing department on 1-844-555-0172 within 24 hours.",
    "आपके खाते से 24 घंटे में $600 काट लिए जाएंगे। रद्द करने के लिए 1-800-555-0147 पर तुरंत कॉल करें।",
    "Aapka subscription renew ho gaya hai, $450 charge hoga. Cancel karne ke liye abhi 1-888-555-0158 par call karein.",
    "Invoice for firewall protection, $529.00. Payment will be auto-processed. Unauthorized? Contact helpdesk: +1 808 555 0191.",
]

LEGIT = [
    "Thanks for your business! Logo design, 3 revisions. Payment due in 30 days.",
    "Invoice for October web hosting. Thank you for being a customer.",
    "Photography session on 2 November, 2 hours, edited photos delivered by link.",
    "Freelance writing: 4 blog posts as agreed. Questions? Reply to this email.",
    "Catering deposit for the event on 14 December as per our signed quote.",
    "Monthly tuition fee for guitar lessons, 4 sessions.",
    "Custom dining table, 50% balance due on delivery as discussed.",
    "Consulting, 6 hours at the agreed rate. Net 15. Thank you!",
]


async def main() -> None:
    if not ec.ENABLED:
        raise SystemExit("ELASTIC_URL / ELASTIC_API_KEY are missing from .env")
    print("Index:", await ec.ensure_index())
    for text in SCAMS:
        await ec.remember(text, label="scam", source="seed")
    for text in LEGIT:
        await ec.remember(text, label="legit", source="seed")
    print(f"Loaded {len(SCAMS)} scam and {len(LEGIT)} legit examples.")

    await asyncio.sleep(3)  # let the index refresh
    hits = await ec.similar_cases("You will be charged $600 tomorrow, call 1-800-555-0100 to cancel")
    print("Search test, top matches:")
    for h in hits[:3]:
        print(f"  [{h['label']}] {h['content'][:70]}")

    if ec.JUDGE_ENABLED:
        print("Judge agent:", await ec.ensure_agent())
        verdict = await ec.ask_judge(
            {"item": "Security Renewal", "amount": "600 USD",
             "sender_text": "Will be charged within 24 hours. To cancel call 1-800-555-0199."},
            ["phone_number", "call_to_cancel"], hits, "en",
        )
        print("Judge test:", verdict or "FAILED (see warning above)")
    else:
        print("KIBANA_URL missing: Judge agent skipped.")
    await ec.aclose()


if __name__ == "__main__":
    asyncio.run(main())