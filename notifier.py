"""Trusted-contact alerts, sent through Zapier MCP (free on every Zapier plan).

Setup: at mcp.zapier.com create an MCP server, add the tool "Gmail: Send Email",
then copy the server URL (with its token) from the Connect tab into .env:

    ZAPIER_MCP_URL=https://mcp.zapier.com/api/v1/connect?token=...

Each alert is one tool call (2 Zapier tasks). Without the setting, alerts are only logged.
A classic Zapier webhook (ZAPIER_HOOK_URL) still works as a fallback.
"""
import asyncio
import json
import logging
import os

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("payguard.notifier")
logging.getLogger("httpx").setLevel(logging.WARNING)  # httpx logs full URLs, which can contain tokens

ZAPIER_MCP_URL = os.getenv("ZAPIER_MCP_URL", "")
ZAPIER_MCP_TOOL = os.getenv("ZAPIER_MCP_TOOL", "send_email")  # part of the tool's name
ZAPIER_HOOK_URL = os.getenv("ZAPIER_HOOK_URL", "")
ENABLED = ZAPIER_MCP_URL.startswith("https://") or ZAPIER_HOOK_URL.startswith("https://")

ACTION_TEXT = {
    "deleted_draft": "PayGuard stopped this invoice before it was sent.",
    "cancelled": "PayGuard cancelled this invoice.",
    "none": "The invoice has NOT been stopped, so they may still see it.",
    "checked": "They checked this invoice on PayGuard themselves.",
}


def build_alert(protected_email: str, contact_name: str, contact_email: str,
                item_name: str, amount: str, result: dict, action: str) -> dict:
    """The payload Zapier receives. `subject` and `message` are ready to send as-is."""
    level = "a likely scam" if result["verdict"] == "LIKELY_SCAM" else "suspicious"
    reasons = "\n".join(f"- {r}" for r in result["reasons"][:3])
    message = (
        f"Hi {contact_name},\n\n"
        f"{protected_email} chose you as their trusted contact on PayGuard.\n\n"
        f"A PayPal invoice addressed to them looks like {level} "
        f"(risk {result['risk_score']}/100).\n\n"
        f"Invoice: {item_name} for {amount}\n"
        f"Why it was flagged:\n{reasons}\n\n"
        f"{ACTION_TEXT.get(action, '')}\n\n"
        "What you can do: call them on a number you already know. Tell them not to call "
        "any phone number written in the invoice, not to install anything, and not to pay.\n\n"
        "PayGuard"
    )
    return {
        "to_email": contact_email,
        "to_name": contact_name,
        "protected_email": protected_email,
        "subject": f"PayGuard alert: {protected_email} got a {level.replace('a ', '')} PayPal invoice",
        "message": message,
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "item": item_name,
        "amount": amount,
        "action": action,
    }


def _parse_rpc(resp: httpx.Response, request_id: int) -> dict:
    """Read a JSON-RPC reply that arrives either as JSON or as an event stream."""
    if resp.status_code >= 400:
        raise RuntimeError(f"Zapier MCP returned HTTP {resp.status_code}: {resp.text[:200]}")
    if "text/event-stream" in resp.headers.get("content-type", ""):
        messages = [json.loads(line[5:]) for line in resp.text.splitlines() if line.startswith("data:") and line[5:].strip()]
    else:
        messages = [resp.json()]
    for msg in messages:
        if msg.get("id") == request_id:
            if "error" in msg:
                raise RuntimeError(f"Zapier MCP error: {msg['error'].get('message', msg['error'])}")
            return msg.get("result", {})
    raise RuntimeError("Zapier MCP sent no reply to the request")


def _wants_list(field_schema: dict) -> bool:
    """True if the tool's schema says this field must be an array."""
    if field_schema.get("type") == "array":
        return True
    options = field_schema.get("anyOf") or field_schema.get("oneOf") or []
    types = [o.get("type") for o in options if isinstance(o, dict)]
    return "array" in types and "string" not in types


async def _send_via_mcp(payload: dict) -> None:
    """Call the Zapier MCP email tool over plain HTTPS (MCP Streamable HTTP). Raises on failure."""
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    # Send the token in a header, not the URL, so it never shows up in logs.
    parts = urlsplit(ZAPIER_MCP_URL)
    query = dict(parse_qsl(parts.query))
    token = query.pop("token", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    mcp_url = urlunsplit(parts._replace(query=urlencode(query)))
    async with httpx.AsyncClient(timeout=60) as http:

        async def rpc(request_id: int, method: str, params: dict) -> dict:
            resp = await http.post(
                mcp_url, headers=headers,
                json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            )
            if resp.headers.get("mcp-session-id"):
                headers["Mcp-Session-Id"] = resp.headers["mcp-session-id"]
            return _parse_rpc(resp, request_id)

        init = await rpc(1, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "payguard", "version": "1.0"},
        })
        headers["MCP-Protocol-Version"] = init.get("protocolVersion", "2025-06-18")
        await http.post(mcp_url, headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})

        tools = (await rpc(2, "tools/list", {})).get("tools", [])
        tool = next((t for t in tools if ZAPIER_MCP_TOOL in t["name"]), None)
        if tool is None:
            raise RuntimeError(
                f"No tool containing '{ZAPIER_MCP_TOOL}' on the Zapier MCP server. "
                f"Tools found: {[t['name'] for t in tools]}"
            )
        fields = (tool.get("inputSchema") or {}).get("properties", {})
        wanted = {
            "instructions": (
                f"Send one plain-text email to {payload['to_email']} with the subject "
                f"\"{payload['subject']}\" and exactly this body, unchanged:\n\n{payload['message']}"
            ),
            "to": payload["to_email"], "recipient": payload["to_email"], "to_email": payload["to_email"],
            "subject": payload["subject"],
            "body": payload["message"], "message": payload["message"], "text": payload["message"],
        }
        args = {k: v for k, v in wanted.items() if k in fields} or {"instructions": wanted["instructions"]}
        for key in list(args):  # some fields (like Gmail's "to") want a list, not a string
            if _wants_list(fields.get(key, {})):
                args[key] = [args[key]]
        result = await rpc(3, "tools/call", {"name": tool["name"], "arguments": args})
        if result.get("isError"):
            detail = " ".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict))
            raise RuntimeError(f"Zapier tool failed: {detail[:300]}")


async def _send_via_webhook(payload: dict) -> None:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(ZAPIER_HOOK_URL, json=payload)
    resp.raise_for_status()


async def send_alert(payload: dict) -> bool:
    """Send the alert through Zapier. Returns True only if Zapier accepted it."""
    if not ENABLED:
        log.warning("ZAPIER_MCP_URL not set; alert for %s was not sent", payload["to_email"])
        return False
    try:
        if ZAPIER_MCP_URL:
            await asyncio.wait_for(_send_via_mcp(payload), timeout=90)
        else:
            await _send_via_webhook(payload)
        log.info("alert sent to trusted contact %s", payload["to_email"])
        return True
    except Exception as exc:
        log.error("could not send alert to %s: %s", payload["to_email"], exc)
        return False


if __name__ == "__main__":  # quick test:  python notifier.py you@example.com
    import sys

    logging.basicConfig(level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    demo = build_alert("protected@example.com", "Test Contact", sys.argv[1], "ShieldPro Security Renewal",
                       "600.00 USD", {"verdict": "LIKELY_SCAM", "risk_score": 95,
                                      "reasons": ["It contains a phone number.", "It sets a 24-hour deadline."]},
                       "deleted_draft")
    print("Sent" if asyncio.run(send_alert(demo)) else "NOT sent (see the message above)")