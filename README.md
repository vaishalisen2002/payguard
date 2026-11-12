# 🛡️ PayGuard

**An AI teammate that reads every PayPal invoice before you act on it — and stops the fake-invoice phone scam cold.**

🔗 **Live demo:** https://payguard-voni.onrender.com · 🎬 **Video:** YOUTUBE_LINK_HERE

---

## 📖 The story, in six panels

| | Without PayGuard | With PayGuard |
|---|---|---|
| **1. The setup** | A scammer opens a *genuine* PayPal account and uses PayPal's own invoicing feature. | Same scammer, same real invoice. |
| **2. The invoice** | *"ShieldPro Security Renewal — $600. Your account will be charged within 24 hours. To cancel, call 1-800-XXX-XXXX."* | The moment the invoice is created, a webhook wakes PayGuard. |
| **3. The trap** | The email comes from PayPal's real system. No fake sender. No suspicious link. Every classic safety tip fails. | Rules catch the phone number and fake deadline. Elastic's semantic memory matches it to reported scams. An AI judge confirms: **scam, 100/100**. |
| **4. The panic** | *"$600 will be taken today!"* The victim calls the number. A friendly "agent" asks for remote access, codes, gift cards. | **The invoice is deleted while still a draft.** The victim never even receives the email. |
| **5. The family** | Older relatives decide alone, under pressure, in seconds. Many lose far more than $600. | Their registered **trusted person gets an email instantly**: *"Call them on a number you already know. Tell them not to call the invoice."* |
| **6. The aftermath** | Victims blamed, trust in digital payments drops, support teams flooded. | Every report feeds a **shared scam memory** — one victim's report protects the next person. |

---

## ✨ What PayGuard does

- **Scans every invoice automatically** — PayPal webhook → fetch → score, in seconds.
- **Stops scams before they land** — conclusive scams are deleted as drafts; already-sent ones are cancelled.
- **Explains in plain words** — "Likely a scam / Be careful / Looks safe" with reasons, in **English or Hindi (हिन्दी)**, in big readable type designed for older users.
- **Tells someone you trust** — register a family member once; they're emailed the moment a risky invoice targets you.
- **Learns from every report** — reported text and phone numbers join a shared blocklist + semantic scam memory.
- **Self-serve check page** — anyone can paste a suspicious invoice at `/check` and get a stamped verdict.

---

## 🤖 The agents

| Agent | Job | Built with |
|---|---|---|
| **Intake** | Receives signature-verified webhooks, fetches the invoice | PayPal Invoicing v2 + Webhooks |
| **Pattern** | Finds similar past scams by meaning, not keywords | Elasticsearch `semantic_text` (Jina embeddings) |
| **Judge** | Weighs rules + memory + invoice text, writes the plain-language verdict (EN/HI) | **Elastic Agent Builder** on Elastic Managed LLM |
| **Action** | Deletes drafts / cancels sent invoices, blocklists phone numbers | PayPal Invoicing v2 |
| **Notifier** | Emails the trusted contact | **Zapier MCP** (Gmail Send Email tool) |

**Safety by design:** only hard evidence (rules + scam memory) can auto-stop an invoice — an LLM hunch alone can only say "Be careful". Text inside an invoice that tries to instruct the AI is itself treated as a scam signal, so prompt injection makes the score go *up*, not down.

```
PayPal sandbox ──webhook──▶ FastAPI (Render)
                              │  fixed rules ──▶ instant stop (draft deleted / invoice cancelled)
                              │  Elastic semantic scam memory (Jina embeddings)
                              │  Elastic Agent Builder "Judge" (Managed LLM, EN/HI verdicts)
                              │  SQLite: scans · blocklist · trusted contacts
                              └─▶ Zapier MCP ──▶ Gmail ──▶ trusted person's inbox
```

---

## 🛠️ Tools used

- **PayPal developer platform (sandbox):** Invoicing v2 (create / get / send / cancel / delete), Webhooks with signature verification, Disputes API (tracking), sandbox Business & Personal test accounts
- **Elastic:** Agent Builder agent ("PayGuard Judge") on Elastic Managed LLMs; Elasticsearch semantic search as the shared scam memory
- **Zapier MCP:** trusted-contact alerts via the Gmail tool over MCP Streamable HTTP
- **Render:** hosting + the fixed public webhook URL
- **FastAPI · httpx · SQLite:** the app itself

---

## 🚀 Run it yourself

Prereqs: Python 3.12+, a PayPal sandbox app, an Elastic Cloud trial, a Zapier account (free plan includes MCP).

```bash
git clone https://github.com/vaishalisen2002/payguard.git
cd payguard
pip install -r requirements.txt
cp .env.example .env        # fill in your keys — table below
python setup_elastic.py     # creates the scam memory + Judge agent, loads seed scams
uvicorn main:app --reload   # open http://127.0.0.1:8000/check
```

| `.env` key | Where it comes from |
|---|---|
| `PAYPAL_CLIENT_ID` / `PAYPAL_CLIENT_SECRET` | Developer dashboard → Apps & Credentials (Sandbox) |
| `PAYPAL_BASE_URL` | `https://api-m.sandbox.paypal.com` |
| `PAYPAL_WEBHOOK_ID` | Sandbox Webhooks table, after adding `https://<your-host>/webhook/paypal` with the invoicing + dispute events |
| `PAYPAL_VERIFY_WEBHOOK` | `true` (use `false` only with PayPal's webhook simulator) |
| `ELASTIC_URL` / `ELASTIC_API_KEY` | Elastic Cloud serverless project (Search type) |
| `KIBANA_URL` | Same project, the `.kb.` host |
| `ZAPIER_MCP_URL` | mcp.zapier.com → your server (managed mode, Gmail: Send Email tool) → API key |

### Reproduce the live-kill demo

```bash
# victim must be a NON-India sandbox Personal account
# (PayPal blocks India-to-India invoicing)
python create_test_invoice.py sb-xxxxx@personal.example.com
```

Expected output: the script creates the $600 "ShieldPro Security Renewal" scam invoice, waits 30 seconds… and the send **fails** — PayGuard already deleted the draft. Watch it appear on `/dashboard` as *"Stopped before it was sent"*, and the registered trusted contact receives the alert email.

---

## ⚠️ Honest limitations

- The automatic scan covers invoices sent by accounts connected to the app (PayPal's API only lets the *sender* read an invoice). We pitch PayGuard as the check PayPal itself should run platform-wide; the `/check` page covers everyone else today.
- Trusted contacts aren't confirmation-verified yet, and alerts come from a Gmail address — a production version would use an authenticated domain or SMS/WhatsApp.
- Scan history lives in SQLite and resets on redeploy; the Elastic scam memory persists.

## 📄 License

MIT — see [LICENSE](LICENSE).
