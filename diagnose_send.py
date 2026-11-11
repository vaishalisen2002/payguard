"""Find out why PayPal rejects the send call. Prints no secrets.

Usage:  python diagnose_send.py victim-sandbox-email@personal.example.com
"""
import asyncio
import sys

import httpx

import paypal_client as pp


async def status_of(http, token, invoice_id) -> str:
    r = await http.get(f"/v2/invoicing/invoices/{invoice_id}",
                       headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    if r.status_code == 200:
        return f"exists, status={r.json().get('status')}"
    return f"HTTP {r.status_code} {r.text[:150]}"


async def main(victim_email: str) -> None:
    token = await pp._get_token()
    invoice = await pp.create_invoice(
        recipient_email=victim_email,
        item_name="Diagnostic test item",
        amount="10.00",
        note="Thank you for your business.",  # harmless text, so PayGuard will not delete it
        business_name="Diagnostic Sender",
    )
    invoice_id = invoice["id"]
    print("Created:", invoice_id)

    auth = {"Authorization": f"Bearer {token}"}
    attempts = [
        ("A: JSON body, Accept json", {"json": {"send_to_invoicer": True},
                                       "headers": {**auth, "Accept": "application/json"}}),
        ("B: empty JSON body {}", {"json": {}, "headers": {**auth, "Accept": "application/json"}}),
        ("C: no body, no Accept", {"headers": {**auth, "Content-Type": "application/json"}}),
        ("D: no body, Accept */*", {"headers": {**auth, "Content-Type": "application/json", "Accept": "*/*"}}),
        ("E: body with send_to_recipient", {"json": {"send_to_recipient": True, "send_to_invoicer": False},
                                            "headers": {**auth, "Accept": "application/json"}}),
    ]
    async with httpx.AsyncClient(base_url=pp.BASE_URL, timeout=30) as http:
        print("Before send:", await status_of(http, token, invoice_id))
        for label, kwargs in attempts:
            r = await http.post(f"/v2/invoicing/invoices/{invoice_id}/send", **kwargs)
            print(f"\n{label}\n  -> HTTP {r.status_code}  content-type={r.headers.get('content-type')}")
            print("  ", r.text[:400].replace("\n", " "))
            if r.status_code < 300:
                print("  SUCCESS with this variant.")
                break
        print("\nAfter:", await status_of(http, token, invoice_id))
    await pp.aclose()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    asyncio.run(main(sys.argv[1]))