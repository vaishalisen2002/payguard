"""Send the demo scam invoice from the sandbox Business account.

Usage:  python create_test_invoice.py victim-sandbox-email@personal.example.com [wait_seconds]

wait_seconds (default 25) is how long the "scammer" waits before pressing send.
Use 0 to send at once and watch PayGuard cancel the invoice after it went out.
The victim account must be outside India: PayPal blocks India-to-India invoices.
"""
import asyncio
import sys

import paypal_client as pp


async def main(victim_email: str, wait_seconds: float = 25) -> None:
    invoice = await pp.create_invoice(
        recipient_email=victim_email,
        item_name="ShieldPro Security Renewal",
        amount="600.00",
        note="Your subscription will be charged within 24 hours. To cancel, call 1-800-555-0199.",
        business_name="ShieldPro Billing",
    )
    print("Created draft invoice:", invoice["id"])

    print(f"Waiting {wait_seconds:g}s before sending, so PayGuard can scan the draft...")
    await asyncio.sleep(wait_seconds)
    try:
        await pp.send_invoice(invoice["id"])
        print("Invoice was SENT. PayGuard should cancel it within a minute; check /dashboard.")
    except pp.PayPalError as exc:
        if exc.status in (404, 422):
            print("Send failed: PayGuard already stopped this invoice.")
        else:
            raise
    finally:
        await pp.aclose()


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    asyncio.run(main(sys.argv[1], float(sys.argv[2]) if len(sys.argv) == 3 else 25))