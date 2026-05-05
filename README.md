# GoUp

![GoUp Logo](assets/logo_goup_github.png)

Self-hosted, multi-tenant uptime monitoring built as a single Go service with SQLite storage and very few operational dependencies.

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![Docker](https://img.shields.io/badge/Docker-multi--arch-2496ED?logo=docker)](https://ghcr.io/xeonixo/goup)

GoUp monitors services, records their status over time, and sends notifications when a monitor changes state. It is designed for operators who want a lightweight monitoring stack they can run and understand without also maintaining a database cluster, message bus, or large frontend application.

---

## What GoUp is

GoUp combines a control plane, monitor scheduler, web UI, and persistence layer into one deployable service.

It is a good fit if you want:

- a self-hosted uptime monitor for small to medium environments
- tenant separation for teams, customers, or environments
- server-side rendered UI instead of a SPA-heavy stack
- SQLite-based storage that is easy to back up
- local users or OIDC per tenant

---

## Key capabilities

| Area | Details |
|---|---|
| Monitor types | HTTPS, HTTP, TCP, ICMP (ping), SMTP, IMAP, DNS, UDP, WHOIS |
| TLS inspection | Certificate validity, expiry date, remaining lifetime |
| Notifications | Email via SMTP, Matrix, and signed Webhooks |
| Authentication | Separate control-plane admin login, plus tenant-level local auth and OIDC |
| Multi-tenancy | Isolated tenants with their own monitor data and auth configuration |
| Admin UI | Manage tenants, auth providers, users, SMTP settings, webhooks, remote nodes, and security settings |
| Remote execution | Run checks from remote nodes in other networks using outbound-only HTTPS |
| Networking | IPv4, IPv6, and dual-stack support for selected monitor types |
| Operations | Single main process, SQLite, Docker image for `amd64` and `arm64` |

---

## Architecture at a glance

GoUp uses two layers of data and access control:

- **Control plane**: global admin area, tenant registry, auth providers, admin account, shared settings, and operational metadata
- **Tenant scope**: per-tenant monitor definitions, results, notification events, and user-facing dashboard data

This keeps deployment simple while still allowing tenant isolation.

### Remote nodes

GoUp can run checks through a remote node agent when the control plane cannot directly reach the target network.

Typical use cases:

- monitoring services inside private LANs or VPN-only networks
- checking internal DNS, APIs, or mail services from the network where they actually live
- separating the monitoring control plane from execution points in other sites or customer environments

The remote node model is intentionally simple:

- the remote node connects outbound to the GoUp control plane over HTTPS
- bootstrap uses a node ID plus a one-time bootstrap key
- the agent then works with short-lived access tokens that rotate regularly
- assigned checks are executed on the remote node and reported back to the control plane
- results flow through the same result, state, incident, and notification pipeline as local checks

From an operator perspective, the flow is:

1. Create a remote node in the tenant admin UI
2. Start the agent with the provided node ID and bootstrap key
3. Assign selected monitors to that remote node in the monitor configuration
4. Review status and heartbeat information in the UI

Important operational notes:

- remote nodes require outbound HTTPS to the GoUp instance, not inbound access from the control plane
- for ICMP checks, the remote node container still needs `NET_RAW`
- the container image can run both the main server and the agent; use `GOUP_MODE=remote-node` for agent mode

For deployment details and the agent-specific environment variables, see [remote-node/README.md](remote-node/README.md).

---

## Quick start

### Prerequisites

- Docker
- Docker Compose

### 1. Create an environment file

```bash
cp .env.example .env
```

Minimal configuration for local startup:

```dotenv
GOUP_ADDR=:8080
GOUP_BASE_URL=http://localhost:8080
GOUP_DATA_DIR=/data
GOUP_LOG_LEVEL=info
```

### 2. Review the Docker volume mapping

The default [docker-compose.yml](docker-compose.yml) mounts `./data` into the container at `/data`.

If you use a bind mount on Linux, ensure the target directory is writable by the container user (`UID 100`, `GID 101`). Example:

```bash
sudo mkdir -p ./data
sudo chown -R 100:101 ./data
```

### 3. Start GoUp

```bash
docker compose up -d
```

### 4. Complete the initial admin setup

On first start, no control-plane admin account exists. Open:

```text
http://localhost:8080/admin/setup
```

Create the admin username and password there. You can also enroll a TOTP authenticator during setup.

### 5. Create your first tenant

After signing in at `/admin/access`:

1. Open **Admin → Tenants**
2. Create a tenant slug such as `prod`
3. Optionally add auth providers or local tenant users
4. Open the tenant dashboard at `http://localhost:8080/prod/`

Important notes:

- The tenant slug becomes part of the URL.
- GoUp does not require a built-in `default` tenant.
- After creating a new tenant, restart the container so the monitor runner for that tenant starts.

### 6. Add monitors

Use **+ Monitor** in the tenant dashboard to create checks. New monitors are scheduled automatically.

### 7. Verify the service health endpoint

```text
http://localhost:8080/healthz
```

### Updating an existing installation

```bash
docker compose pull
docker compose up -d
```

---

## First-run workflow

If you are evaluating GoUp for the first time, the usual sequence is:

1. Start the service and create the control-plane admin account
2. Create one tenant per environment, team, or customer
3. Configure tenant access with local users and/or OIDC
4. Add monitors and notification settings
5. Confirm the first successful check results in the dashboard

---

## Configuration reference

Configuration is provided through environment variables, typically via `.env` and Docker Compose.

### Core settings

| Variable | Default | Description |
|---|---|---|
| `GOUP_ADDR` | `:8080` | Bind address for the HTTP server |
| `GOUP_BASE_URL` | `http://localhost:8080` | External base URL used for CSRF validation, OIDC callbacks, and generated links |
| `GOUP_DATA_DIR` | `/data` | Directory containing all SQLite database files |
| `GOUP_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

### Security-related settings

| Variable | Description |
|---|---|
| `GOUP_SESSION_KEY` | HMAC key for session cookies. If left empty, GoUp generates one automatically and persists it in the control-plane database. Use an explicit value in production. |
| `GOUP_SSO_SECRET_KEY` | Encryption key for OIDC client secrets and TOTP secrets. If empty, GoUp falls back to `GOUP_SESSION_KEY`. |

Production recommendation:

- Set both keys explicitly
- Store them securely
- Treat key loss as credential loss for encrypted secrets stored in the database

---

## Authentication model

GoUp separates **control-plane administration** from **tenant access**.

### Control-plane admin

The admin area under `/admin/*` has its own login independent of tenant users.

- Initial setup: `/admin/setup`
- Login: `/admin/access`
- TOTP management: `/admin/security`

### Tenant authentication

Authentication is configured per tenant.

| Tenant state | Result |
|---|---|
| No auth providers or tenant users configured | No tenant login is available |
| Local users configured | Sign in with username and password |
| OIDC provider configured | Sign in via the configured OIDC provider |
| Both configured | The tenant login page offers both options |

Auth providers are managed in the admin UI under **Tenants → Providers**. Local users are managed under **Tenants → Users**.

### OIDC / Authentik note

For an OIDC provider such as Authentik:

- **Issuer URL** must match the OpenID Connect issuer
- **Redirect URI** must point to `https://your-domain/{tenantSlug}/auth/callback`

---

## Monitor types and targets

| Type | Expected target format | Example |
|---|---|---|
| `https` | URL | `https://example.com/health` |
| `http` | URL | `http://internal-service:8080/` |
| `tcp` | `host:port` | `db.internal:5432` |
| `icmp` | Hostname or IP address | `192.168.1.1` |
| `smtp` | `host:port` | `mail.example.com:587` |
| `imap` | `host:port` | `mail.example.com:993` |
| `dns` | Hostname | `example.com` |
| `udp` | `host:port` | `ntp.example.com:123` |
| `whois` | Domain name | `example.com` |

Additional behavior:

- HTTPS monitors extract TLS certificate metadata automatically
- SMTP and IMAP support both direct TLS and STARTTLS
- Existing legacy URL-style HTTPS monitor entries remain supported

### IPv4, IPv6, and dual-stack

For `https`, `tcp`, `icmp`, and `udp`, the UI can select the IP family when a hostname is used:

- `IPv4`
- `IPv6`
- `Dual Stack`

When the target is already a literal IP address, no family selection is required.

### HTTP and HTTPS input model

The UI uses separate fields for:

- host or IP
- port
- path and query

If no port is specified, GoUp uses:

- `443` for HTTPS
- `80` for HTTP

### UDP probe modes

Current UDP monitors support the following active probe types in the UI:

- DNS reachability
- NTP check

Suggested default ports:

- DNS: `53`
- NTP: `123`

Legacy UDP monitor modes remain backend-compatible, but only the current supported modes are exposed in the create/edit UI.

---

## Dashboard behavior

The dashboard is meant to be readable without a heavy client-side app.

Notable UI behavior:

- “Last updated” timestamps are rendered client-side as compact relative durations such as `10 sec.`, `1 min. 25 sec.`, or `1 h 45 min.`
- Relative time labels adapt to the browser locale
- Each monitor shows a cycle indicator for the expected next check time

### One-shot checks

Admins can trigger an immediate one-off monitor run from the dashboard.

- The cycle icon next to the status becomes clickable for admins
- Clicking it triggers exactly one immediate check
- The normal interval schedule remains unchanged afterward
- Running checks are shown visually in the UI

Permission behavior:

- In tenants with authentication enabled, only admins can trigger one-shot checks
- For non-admin users, the indicator remains informational only

---

## Notifications

### Email

Email delivery is configured in the admin UI under **Settings → SMTP**.

GoUp sends notifications to tenant users who have email notifications enabled.

### Matrix

Each user can configure Matrix settings in their profile at `/{tenantSlug}/settings/profile`, including:

- homeserver URL
- room ID
- access token

### Webhooks

Tenant admins can configure webhooks at `/{tenantSlug}/settings/webhooks`.

For a local verification receiver, see [docs/webhook_receiver_example.md](docs/webhook_receiver_example.md).

Current behavior:

- webhooks are configured per tenant and fan out to all enabled endpoints in that tenant
- secrets are encrypted in the control-plane database
- only `https` targets are accepted
- redirects are blocked
- loopback, private, link-local, multicast, and other non-public target ranges are blocked to reduce SSRF risk
- each endpoint can be tested directly from the UI with **Send test**

#### Payload

GoUp sends JSON payloads like this for monitor state changes:

```json
{
  "event_type": "status_transition_webhook",
  "tenant_id": 7,
  "endpoint_id": 3,
  "occurred_at": "2026-05-05T12:00:00Z",
  "monitor": {
    "id": 42,
    "name": "Public API",
    "kind": "https",
    "target": "https://api.example.com/health",
    "group": "production"
  },
  "transition": {
    "previous": "down",
    "current": "up",
    "checked_at": "2026-05-05T11:59:58Z",
    "result_detail": "HTTP 200 in 143ms"
  }
}
```

Manual test sends use the same shape but with `event_type = "test_notification_webhook"` and a synthetic monitor like `GoUp Webhook Test`.

#### Headers and signature

Each webhook request includes these headers:

- `Content-Type: application/json`
- `User-Agent: GoUp-Webhook/1.0`
- `X-GoUp-Event: <event type>`
- `X-GoUp-Tenant-ID: <tenant id>`
- `X-GoUp-Endpoint-ID: <endpoint id>`
- `X-GoUp-Timestamp: <RFC3339 timestamp>`
- `X-GoUp-Signature: v1=<hex hmac sha256>`

The signature input is:

```text
<timestamp>.<raw-request-body>
```

The HMAC key is the configured webhook secret and the hash algorithm is SHA-256.

Minimal verification example in Go:

```go
mac := hmac.New(sha256.New, []byte(secret))
mac.Write([]byte(timestamp))
mac.Write([]byte("."))
mac.Write(body)
expected := "v1=" + hex.EncodeToString(mac.Sum(nil))
valid := hmac.Equal([]byte(signature), []byte(expected))
```

---

## Running behind a reverse proxy

GoUp validates `Origin` and `Referer` on state-changing requests against `GOUP_BASE_URL`.

That means:

- `GOUP_BASE_URL` must be set to the public external URL
- the reverse proxy must forward the correct `Host` header
- HTTPS deployments automatically enable secure cookies and HSTS behavior

Minimal Nginx example:

```nginx
location / {
  proxy_pass http://127.0.0.1:8080;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
}
```

---

## ICMP / ping requirements

ICMP checks require the container capability `NET_RAW`.

The provided Compose files already include that capability.

---

## Data storage and backups

GoUp stores data in SQLite files inside `GOUP_DATA_DIR`.

| File | Purpose |
|---|---|
| `controlplane.db` | Tenants, auth providers, users, admin account, SMTP settings, audit and operational metadata |
| `<tenant>.db` | Tenant-specific monitors, results, and notification events |

Backup recommendations:

- back up all `.db` files in the data directory
- include `-wal` and `-shm` files if the service is live during backup
- test restore procedures in a staging environment

---

## Repository structure

```text
cmd/goup/               Main server entrypoint
cmd/remote-node/        Remote node agent entrypoint
internal/app/           Application bootstrap and wiring
internal/config/        Environment-based configuration
internal/auth/          Sessions, OIDC, dynamic OIDC, TOTP
internal/httpserver/    Handlers, middleware, admin UI
internal/monitor/       Monitor models, checkers, scheduler, runner
internal/notify/email/  Email notification delivery
internal/notify/matrix/ Matrix notification delivery
internal/remotenode/    Remote node runtime logic
internal/store/sqlite/  Control-plane and tenant persistence
web/templates/          Server-rendered HTML templates
web/static/             Frontend assets
docs/                   Architecture notes and project documentation
```

---

## Roadmap

- [ ] Public status page
- [ ] Finer-grained roles and permissions
- [ ] Additional monitor types

---

## License

MIT. Self-hosting is encouraged and pull requests are welcome.

