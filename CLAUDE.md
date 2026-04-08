# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build -trimpath -ldflags='-s -w' -o /tmp/goup ./cmd/goup
go build -trimpath -ldflags='-s -w' -o /tmp/remote-node ./cmd/remote-node

# Test all packages
go test ./...

# Run a single test
go test ./internal/monitor/... -run TestFunctionName

# Vet
go vet ./...

# Docker (production)
docker compose up -d
```

## Architecture

GoUp is a self-hosted uptime monitoring service. It runs as a **single Go process** with **SQLite** (no external DB required), multi-tenant isolation, and SSR web UI (no SPA). Two binaries: `goup` (main server) and `remote-node` (optional distributed check agent).

### Startup sequence (`internal/app/app.go`)
1. Load config from env vars (`internal/config/config.go`)
2. Open SQLite databases: one control-plane DB + one DB per tenant
3. Create a `Runner` per active tenant via `buildTenantRunner(...)`
4. Start HTTP server
5. Background goroutines: runner reconcile (30s), remote-node heartbeat watch (30s), DB maintenance

### Key subsystems

| Package | Responsibility |
|---|---|
| `internal/app` | Bootstrap, wiring, lifecycle, runner reconciliation |
| `internal/monitor` | Scheduler + worker pool, checker implementations (HTTPS/TCP/ICMP/SMTP/IMAP/DNS/UDP/WHOIS) |
| `internal/httpserver` | Route registration, all HTTP handlers, middleware |
| `internal/auth` | HMAC session cookies, OIDC (per-tenant dynamic), TOTP |
| `internal/store/sqlite` | Tenant store, control-plane store, `TenantStoreManager` |
| `internal/notify` | Email (SMTP) and Matrix notifiers |
| `internal/remotenode` | Remote node agent (distributed check execution) |
| `web/` | Go templates (`templates/`), static assets (`static/`), i18n (`i18n/`) |

### Multi-tenancy
- Control plane: `controlplane.db` — stores tenants, providers, admin credentials
- Per-tenant: separate `<slug>.db` (or configured `db_path`) — stores monitors, results, events
- **`TenantStoreManager`** is the single owner of all tenant DB connections; runners always obtain stores via `StoreForTenant(...)`, never by opening DBs directly
- Multi-tenant maintenance (retention/rollup/optimize) runs via `runMaintenanceOnce(...)` which iterates all active tenant stores

### Runner & worker pool (`internal/monitor/runner.go`)
- Ticks every 5s; collects all due snapshots, dispatches them through a **bounded worker pool (4 workers)** via semaphore
- Single-check logic lives in `runSnapshot(...)`
- Runner reconcile loop in `app.go` detects tenant changes (activation, config changes) and starts/stops runners dynamically without restart

### HTTP server (`internal/httpserver/`)
- `server.go` — route registration, upgrader setup, lockout maps, security state
- `logging_middleware.go` — request logging (method, path, duration, status, bytes) via `loggingResponseWriter`
- `password_reset_tokens.go` — HMAC-signed tokens with in-memory one-time-use replay protection
- `security_state.go` — sweeper for lockout maps (`localLoginAttempts`, `adminAccessAttempts`, `bootstrapAttempts`)
- Remote node endpoints (`/node/bootstrap|poll|report`) enforce `http.MaxBytesReader` + `DisallowUnknownFields`

### Remote node authentication
Access tokens are stored with a `sha256(token)` fingerprint indexed in SQLite — authentication does a direct indexed lookup, not a linear scan.

### Key interfaces
- `monitor.Checker` — implemented per protocol; used by runner
- `monitor.Notifier` — implemented by email/matrix notifiers
- `monitor.Store` — data access for snapshots, results, state events

## Conventions

- **No ORM** — raw SQL throughout; migrations inline in store constructors
- **No heavy frameworks** — stdlib `net/http`, minimal third-party deps
- **Contexts everywhere** — all blocking operations accept `context.Context`; graceful shutdown via cancellation
- **Encryption** — OIDC client secrets encrypted with AES-GCM in the control-plane store; session cookies HMAC-signed
- **SQLite settings** — WAL mode + `busy_timeout` for concurrency; periodic maintenance jobs (cleanup, hourly rollup, VACUUM)
- **Assets embedded** — `web/` directory embedded into the binary via `go:embed`

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `GOUP_ADDR` | `:8080` | HTTP bind address |
| `GOUP_BASE_URL` | `http://localhost:8080` | External URL (CSRF, OIDC redirects) |
| `GOUP_DATA_DIR` | `/data` | SQLite database directory |
| `GOUP_SESSION_KEY` | auto-generated | HMAC key for session cookies (min 16 chars) |
| `GOUP_SSO_SECRET_KEY` | falls back to session key | AES-GCM key for OIDC secret encryption |
| `GOUP_CONTROL_PLANE_ADMIN_KEY` | — | Cookie key for admin area |
| `GOUP_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |
| `GOUP_OIDC_ISSUER_URL` | — | Global OIDC provider (optional) |
