# GoUp

![GoUp Logo](assets/logo_goup_github.png)

Self-hosted, multi-tenant uptime monitoring built as a single Go service with SQLite storage and very few operational dependencies.

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev)
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
| Notifications | Email via SMTP, Matrix, signed Webhooks, and Web Push |
| Outage reminders | Optional per-monitor reminder (15 min to 24 h) while a monitor stays down; see [Outage reminders](#outage-reminders) |
| Maintenance windows | Planned, optionally recurring windows (all monitors, groups, or selected monitors): no alerts, excluded from uptime, shown as "Maintenance"; see [Maintenance windows](#maintenance-windows) |
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
# Generate each key independently: openssl rand -hex 32
GOUP_SESSION_KEY=<output of openssl rand -hex 32>
GOUP_SSO_SECRET_KEY=<another, different openssl rand -hex 32>
GOUP_CONTROL_PLANE_ADMIN_KEY=<a third, different openssl rand -hex 32>
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
| `GOUP_MONITOR_WORKERS` | `4` | Maximum number of local monitor checks running concurrently |
| `GOUP_TRUSTED_PROXIES` | _(empty)_ | Comma separated CIDRs/IPs of reverse proxies whose `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto` headers are trusted. See [Running behind a reverse proxy](#running-behind-a-reverse-proxy). |
| `GOUP_SETUP_TOKEN` | _(random)_ | Token required for the initial `/admin/setup` form. If unset, a random token is generated at startup and written to the server log while setup is pending. |
| `GOUP_MONITOR_ALLOW_PRIVATE` | `true` | Allow monitors to reach private/loopback networks. Cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) are always blocked. |
| `GOUP_ALLOW_PRIVATE_INTEGRATIONS` | `false` | Allow the Matrix homeserver URL and OIDC issuer URLs to point at private/loopback addresses. Default is public https only (SSRF protection). **Set to `true` if your Keycloak/Matrix runs on your LAN.** |
| `GOUP_REMOTE_NODE_ALLOW_INSECURE` | `false` | Remote-node agent only: permit a plain `http://` control-plane URL (otherwise https is required, except `localhost`/`127.0.0.1`). |

### Security-related settings

| Variable | Description |
|---|---|
| `GOUP_SESSION_KEY` | Required HMAC key for tenant session cookies and password-reset tokens. |
| `GOUP_SSO_SECRET_KEY` | Required encryption key for stored secrets, including OIDC client secrets, TOTP secrets, notification secrets, and remote-node secrets. |
| `GOUP_CONTROL_PLANE_ADMIN_KEY` | Required HMAC key for control-plane admin cookies under `/admin/*`. |

All three keys must be at least 32 characters, must be different from each
other and must not be the `replace-with-...` placeholders from the example
file. GoUp refuses to start otherwise and prints which key is invalid.

Generate each key independently with 32 random bytes encoded as hex:

```bash
openssl rand -hex 32
```

Example `.env` values:

```env
GOUP_SESSION_KEY=1f2d8c3b9a4e6f00112233445566778899aabbccddeeff001122334455667788
GOUP_SSO_SECRET_KEY=9c7e1a5b3d2f4c6e8899aabbccddeeff00112233445566778899aabbccddeeff
GOUP_CONTROL_PLANE_ADMIN_KEY=6b8d0f2a4c1e3d5f77889900aabbccddeeff00112233445566778899aabbcc
```

Keep these values stable across restarts and backups. Do not reuse the same
value for multiple keys. If keys are added or changed after GoUp has already
stored data, the effects are:

- Changing `GOUP_SESSION_KEY` invalidates existing tenant session cookies and password-reset tokens.
- Changing `GOUP_SSO_SECRET_KEY` can make encrypted stored secrets unreadable unless the new value matches the previous effective encryption key.
- Changing `GOUP_CONTROL_PLANE_ADMIN_KEY` invalidates current control-plane admin cookies; admins can log in again.

Treat key loss as credential loss for encrypted secrets stored in the database.

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

While a monitor stays down and a reminder interval is configured, GoUp repeats the alert with `event_type = "status_reminder_webhook"`: `transition.previous` and `transition.current` are both `down`, `transition.reminder` is `true` and `transition.outage_seconds` holds the outage duration. The summary sent after a mute or maintenance window has `transition.catch_up = true`.

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

## Outage reminders

Each monitor has an **Repeat outage alert** setting (advanced section of the monitor dialog; also part of monitor export/import as `remind_every_minutes`): off (default), 15, 30 min, 1, 2, 4, 12 or 24 h.

- Applies only while the monitor is **down** (not degraded) and its down alert was actually announced (respecting "alert after N failures").
- The interval is measured from the last announcement (the down alert or the previous reminder). The timestamp is stored in the database (`monitors.last_alert_at`), so a restart neither loses nor duplicates reminders. It is cleared as soon as the monitor is no longer down.
- No reminders while the monitor is muted or inside a maintenance window. When a mute or window ends and the outage continues, the next reminder follows as soon as it is due.
- All channels receive it: email ("[STILL DOWN] name: down for 2 h 15 min"), Matrix, Web Push (own "Reminders" preference per device) and webhooks (`event_type: status_reminder_webhook`, see above).
- A failed delivery is queued for retry at most once per reminder and channel; an older queued reminder is dropped when a newer one is queued, and a queued reminder is dropped when the monitor recovered, was muted, entered maintenance, or reminders were switched off.

## Maintenance windows

Tenant admins manage windows under **Settings → Maintenance windows** (`/{slug}/settings/maintenance`).

- A window has a title, optional internal description, start and end, a repetition (**one time**, **daily**, **weekly**) and a scope: all monitors, selected groups, or selected monitors.
- Recurring windows repeat the same span every 24 hours / 7 days. Occurrences are computed in plain UTC, so across a daylight-saving change the local wall-clock time shifts by one hour. A recurring window must not be longer than its period.
- **Time zone:** start and end are entered in the browser's time zone; a small script converts them to UTC instants before submitting (hidden `starts_at`/`ends_at`), and times are displayed in the browser time zone as well. Without JavaScript the entered values are interpreted as UTC. Windows are stored in UTC.
- While a window covers a monitor, checks keep running and are stored with `in_maintenance = 1`. They count towards `total_checks` and `maintenance_checks` of the hourly rollup but not towards up/down/degraded, so they do not lower uptime. No notifications are sent, no incident or state-change event is created for downtime inside the window, and no reminders are sent.
- When the window ends, one summary notification is sent if the monitor's status differs from its status before the window (same mechanism as the mute catch-up; the marker is `monitors.mute_start_status`).
- The dashboard card, group header and detail page show a "Maintenance" status; the monitor menu has a quick action **Start maintenance (1 h)**.
- The public status page lists running and upcoming (next 7 days) windows that affect at least one shown monitor (title and time range only) and shows "Maintenance" for covered monitors.
- Prometheus: `goup_monitor_in_maintenance` is 1 while a window covers the monitor.
- The server caches the windows for up to 30 seconds; changes made through the UI take effect immediately.

## Public status page

Each tenant can publish an opt-in status page at `/{slug}/status`. It needs no login and is disabled by default.

1. Sign in as a tenant admin and open **Settings → Status & metrics**.
2. Enable the page, set a title and optional description, tick the monitors to show and give each a public display name (defaults to the monitor name). Use **Copy public URL** to share the link.

The page shows an overall banner, each monitor's current status, 90-day daily uptime bars with the percentage (computed from the hourly rollups, so unknown and maintenance checks do not count) and the time of the last update. It never exposes targets, hosts, URLs, error messages or latencies. If a selected monitor belongs to a monitor group, the group name is shown as a heading. The response is cached on the server for 30 seconds and sent with `Cache-Control: public, max-age=30`, so changes appear after at most about 30 seconds. A disabled page or an inactive tenant returns 404.

## Prometheus metrics

`GET /{slug}/metrics` serves tenant metrics in the Prometheus text exposition format (0.0.4). The endpoint requires a bearer token:

1. In **Settings → Status & metrics → API tokens for metrics** a tenant admin creates a token. It is shown once; only its SHA-256 hash is stored. Tokens can be revoked at any time.
2. Add a scrape job:

```yaml
scrape_configs:
  - job_name: goup-acme
    scheme: https
    metrics_path: /acme/metrics
    authorization:
      type: Bearer
      credentials: goup_xxxxxxxxxxxxxxxx   # or credentials_file: /etc/prometheus/goup.token
    static_configs:
      - targets: ["goup.example.com"]
```

(Older Prometheus versions use `bearer_token` / `bearer_token_file` instead of `authorization`.)

Exposed series, labelled with `monitor`, `monitor_id`, `kind` and `group`:

| Metric | Meaning |
| --- | --- |
| `goup_monitor_up` | 1 for up/degraded, 0 for down (absent without a verdict) |
| `goup_monitor_status{status=...}` | one-hot: `up`, `degraded`, `down`, `unknown`, `paused` |
| `goup_monitor_latency_milliseconds` | latency of the last up/degraded check |
| `goup_monitor_cert_expiry_timestamp_seconds` | certificate expiry (Unix time), if known |
| `goup_monitor_uptime_ratio{window="24h\|7d\|30d"}` | uptime ratio 0-1 from the hourly rollups |
| `goup_monitor_paused`, `goup_monitor_muted` | 1 if the monitor is paused / muted |
| `goup_monitor_in_maintenance` | 1 while a maintenance window covers the monitor |
| `goup_monitor_last_check_timestamp_seconds` | time of the last check |
| `goup_build_info{version=...}` | build information |

Repeated requests with an invalid token are rate limited per client IP (HTTP 429). Monitor targets and hosts are never part of the output.

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
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

Set `GOUP_TRUSTED_PROXIES` to the address(es) of the proxy as seen by GoUp
(for example `GOUP_TRUSTED_PROXIES=172.19.27.1/32` or the Docker network CIDR).
Only then are forwarded headers used for the client IP (rate limits, login
lockouts, audit log, remote-node events) and for deciding that the connection
is HTTPS (`Secure` admin cookies, HSTS). The rightmost untrusted
`X-Forwarded-For` hop is used; IPv6 clients are rate-limited per `/64`.
Without `GOUP_TRUSTED_PROXIES` every client appears with the proxy's IP, so
a single attacker can lock out all users of a tenant; configure it.

Session cookies are marked `Secure` based on `GOUP_BASE_URL` (use an `https://`
base URL behind a TLS-terminating proxy).

### Initial setup token

While no control-plane admin exists, `/admin/setup` requires a setup token:
either `GOUP_SETUP_TOKEN` or the random token printed to the log at startup
(`CONTROL-PLANE SETUP PENDING`). This prevents anyone who can reach a fresh
instance from claiming the admin account.

### OIDC access policy

Each OIDC provider has a *role for new users* (default `viewer`), optional
*allowed email domains* and optional *allowed groups* (matched against the
`groups` claim). Users whose `email_verified` claim is `false` are rejected; if
domains are configured a verified email is required. Existing members keep
their role on later logins. Users removed from a tenant are blocked (not
deleted) so they cannot silently rejoin via SSO; use "Re-add" in the user
list to allow them again.

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
