# Webhook receiver example (local signature verification)

This example is a minimal Go HTTP receiver for GoUp webhooks with:

- HMAC signature verification (`X-GoUp-Signature`)
- timestamp skew check (`X-GoUp-Timestamp`)
- JSON payload parsing and structured logging

Source file: [docs/webhook_receiver_example.go](docs/webhook_receiver_example.go)

## 1) Run the receiver

From the repository root:

```bash
WEBHOOK_SECRET='replace-with-your-webhook-secret' \
WEBHOOK_ADDR=':8090' \
WEBHOOK_PATH='/webhook' \
go run ./docs/webhook_receiver_example.go
```

Optional environment variables:

- `WEBHOOK_MAX_SKEW_SECONDS` (default: `300`)

## 2) Expose it via HTTPS

GoUp only sends to public HTTPS targets and blocks loopback/private targets. For local testing, expose the receiver through an HTTPS tunnel or a public reverse proxy.

Example flow:

1. Start receiver locally on `:8090`
2. Expose it using your preferred tunnel (`https://...`)
3. Configure the tunnel URL + `/webhook` in `/{tenantSlug}/settings/webhooks`
4. Click **Send test** for that endpoint

## 3) Expected success behavior

The receiver returns `204 No Content` and logs entries like:

```text
webhook ok event=status_transition_webhook tenant=7 endpoint=3 monitor="Public API" kind=https target="https://api.example.com/health" transition=down->up detail="HTTP 200 in 143ms"
```

For manual tests from the UI, event type is `test_notification_webhook`.
