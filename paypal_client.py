"""PayPal REST client for PayGuard (sandbox by default).

Async, one shared connection pool, cached OAuth token, clear errors.
"""
import asyncio
import json
import os
import time

import httpx
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.getenv("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID", "")

_http = httpx.AsyncClient(base_url=BASE_URL, timeout=httpx.Timeout(15.0, connect=5.0))
_token = {"value": None, "expires_at": 0.0}
_token_lock = asyncio.Lock()


class PayPalError(Exception):
    """A PayPal API call failed. Carries the status and PayPal's debug_id."""

    def __init__(self, status: int, body):
        self.status = status
        self.body = body
        name = body.get("name", "") if isinstance(body, dict) else ""
        message = body.get("message", "") if isinstance(body, dict) else str(body)[:300]
        debug_id = body.get("debug_id", "") if isinstance(body, dict) else ""
        super().__init__(f"PayPal {status} {name}: {message} (debug_id={debug_id})")


async def aclose() -> None:
    await _http.aclose()


# ---------- auth ----------

async def _get_token(force: bool = False) -> str:
    """Return a cached access token; fetch a new one only when it is about to expire."""
    async with _token_lock:
        if not force and _token["value"] and time.time() < _token["expires_at"]:
            return _token["value"]
        if not CLIENT_ID or not CLIENT_SECRET:
            raise RuntimeError("PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET are missing from .env")
        resp = await _http.post(
            "/v1/oauth2/token",
            auth=(CLIENT_ID, CLIENT_SECRET),
            data={"grant_type": "client_credentials"},
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            raise PayPalError(resp.status_code, _safe_json(resp))
        data = resp.json()
        _token["value"] = data["access_token"]
        _token["expires_at"] = time.time() + int(data.get("expires_in", 300)) - 60
        return _token["value"]


def _safe_json(resp: httpx.Response):
    try:
        return resp.json()
    except ValueError:
        return resp.text


async def _request(method: str, path: str, *, headers: dict | None = None, **kwargs) -> httpx.Response:
    """Authorised request. Retries once if the token was rejected."""
    for attempt in (1, 2):
        token = await _get_token(force=(attempt == 2))
        resp = await _http.request(
            method,
            path,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", **(headers or {})},
            **kwargs,
        )
        if resp.status_code == 401 and attempt == 1:
            continue
        if resp.status_code >= 400:
            raise PayPalError(resp.status_code, _safe_json(resp))
        return resp
    raise RuntimeError("unreachable")


# ---------- invoices ----------

async def create_invoice(
    recipient_email: str,
    item_name: str,
    amount: str,
    note: str,
    *,
    currency: str = "USD",
    business_name: str = "Support Team",
) -> dict:
    """Create a DRAFT invoice and return the full invoice (including its id)."""
    payload = {
        "detail": {
            "currency_code": currency,
            "note": note,
            "payment_term": {"term_type": "DUE_ON_RECEIPT"},
        },
        "invoicer": {"business_name": business_name},
        "primary_recipients": [{"billing_info": {"email_address": recipient_email}}],
        "items": [
            {
                "name": item_name,
                "quantity": "1",
                "unit_amount": {"currency_code": currency, "value": amount},
            }
        ],
    }
    # Without this header PayPal returns only a link, not the invoice.
    resp = await _request(
        "POST", "/v2/invoicing/invoices", json=payload, headers={"Prefer": "return=representation"}
    )
    data = resp.json()
    if "id" in data:
        return data
    href = data.get("href", "")
    return await get_invoice(href.rstrip("/").rsplit("/", 1)[-1])


async def get_invoice(invoice_id: str) -> dict:
    return (await _request("GET", f"/v2/invoicing/invoices/{invoice_id}")).json()


async def send_invoice(invoice_id: str) -> int:
    resp = await _request(
        "POST", f"/v2/invoicing/invoices/{invoice_id}/send", json={"send_to_invoicer": True}
    )
    return resp.status_code


async def cancel_invoice(invoice_id: str, note: str) -> int:
    """Cancel an invoice that was already sent."""
    payload = {
        "subject": "Invoice cancelled",
        "note": note,
        "send_to_invoicer": True,
        "send_to_recipient": True,
    }
    return (await _request("POST", f"/v2/invoicing/invoices/{invoice_id}/cancel", json=payload)).status_code


async def delete_invoice(invoice_id: str) -> int:
    """Delete an invoice that is still a draft (cancel does not work on drafts)."""
    return (await _request("DELETE", f"/v2/invoicing/invoices/{invoice_id}")).status_code


async def stop_invoice(invoice_id: str, status: str, note: str) -> str:
    """Stop an invoice whatever state it is in. Returns the action taken."""
    status = (status or "").upper()
    if status in ("DRAFT", "SCHEDULED"):
        await delete_invoice(invoice_id)
        return "deleted_draft"
    if status in ("SENT", "UNPAID", "PAYMENT_PENDING"):
        await cancel_invoice(invoice_id, note)
        return "cancelled"
    return "none"  # already paid, cancelled or refunded


# ---------- disputes ----------

async def list_disputes(status: str | None = None) -> dict:
    params = {"dispute_state": status} if status else None
    return (await _request("GET", "/v1/customer/disputes", params=params)).json()


async def get_dispute(dispute_id: str) -> dict:
    return (await _request("GET", f"/v1/customer/disputes/{dispute_id}")).json()


# ---------- webhooks ----------

async def verify_webhook_signature(headers, raw_body: bytes) -> bool:
    """Ask PayPal whether this webhook really came from PayPal.

    The raw body is embedded untouched: re-serialising the JSON can change it
    and make a genuine event fail verification.
    """
    if not WEBHOOK_ID:
        raise RuntimeError("PAYPAL_WEBHOOK_ID is missing from .env")
    fields = {
        "transmission_id": headers.get("paypal-transmission-id"),
        "transmission_time": headers.get("paypal-transmission-time"),
        "cert_url": headers.get("paypal-cert-url"),
        "auth_algo": headers.get("paypal-auth-algo"),
        "transmission_sig": headers.get("paypal-transmission-sig"),
        "webhook_id": WEBHOOK_ID,
    }
    if not all(fields.values()):
        return False
    body = json.dumps(fields)[:-1] + ',"webhook_event":' + raw_body.decode("utf-8") + "}"
    try:
        resp = await _request("POST", "/v1/notifications/verify-webhook-signature", content=body)
    except PayPalError:
        return False
    return resp.json().get("verification_status") == "SUCCESS"