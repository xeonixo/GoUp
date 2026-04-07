# GoUp – Comprehensive Project Documentation & Code Review

Date: 2026-04-07  
Repository: GoUp

---

## 1. Executive Summary

GoUp is a self-hosted uptime monitoring platform written in Go, centered around:

- a single primary server process,
- SQLite for persistence,
- server-side rendered HTML UI,
- tenant-aware authentication (local users and OIDC),
- monitor execution for multiple protocols,
- optional remote execution via Remote Node agents,
- tenant-scoped notifications (Email + Matrix).

The architecture is pragmatic, operationally lightweight, and well aligned for small to medium self-hosted environments. The project demonstrates strong practical security controls (cookie settings, origin/referer checks, lockout mechanisms, encrypted secrets at rest) and robust protocol coverage.

The most important technical improvement opportunities are:

1. **Scalability of remote node token validation** (linear scan over candidates).
2. **Maintenance and runner lifecycle in multi-tenant mode** (currently startup-centric and partially default-tenant-centric).
3. **Large monolithic HTTP server implementation** (maintainability, testability).
4. **Test coverage breadth** (currently mostly monitor package).

---

## 2. Scope & Review Method

This review is based on direct inspection of core source files and runtime checks.

### Reviewed areas

- App bootstrap and runtime orchestration
- HTTP routing/middleware/security headers/origin protection
- Authentication/session/OIDC/TOTP components
- Monitor engine and protocol checkers
- SQLite store layer (control-plane + tenant data + maintenance)
- Remote node protocol and agent
- Notification stack (Email/Matrix)
- Configuration and deployment references

### Automated checks executed

- `go test ./...` (all packages)
- `go vet ./...`

### Result snapshot

- Tests pass where present.
- Most packages currently have no test files.
- `go vet` produced no diagnostics.

---

## 3. High-Level System Overview

## 3.1 Runtime Components

### Main server (`cmd/goup`)

Bootstraps full application lifecycle:

- configuration loading,
- data dir creation,
- control-plane DB setup,
- tenant store management,
- notifier wiring,
- monitor runners per active tenant,
- HTTP server startup.

### Remote node agent (`cmd/remote-node`)

A separate executable polling the control-plane for assigned checks, executing them, and reporting results.

## 3.2 Primary Design Characteristics

- Single-process control plane (simpler operations and debugging)
- SSR UI (lighter frontend complexity)
- SQLite with migration-by-startup patterns
- Tenant isolation by per-tenant database path
- Explicit monitor and notification event recording

---

## 4. Repository Structure (Functional View)

- `cmd/goup`: main server entrypoint
- `cmd/remote-node`: remote execution agent entrypoint
- `internal/app`: top-level composition/wiring
- `internal/httpserver`: HTTP handlers, middleware, templating integration
- `internal/auth`: sessions, OIDC, dynamic OIDC, TOTP
- `internal/monitor`: monitor domain model, runner, protocol checkers
- `internal/store/sqlite`: data layer, schema migration helpers, maintenance, control-plane and tenant stores
- `internal/notify/email`: SMTP-based email notifications with i18n support
- `internal/notify/matrix`: Matrix notifications
- `internal/remotenode`: remote node runtime logic
- `web/templates` and `web/static`: SSR templates and client-side assets
- `docs`: architecture and additional docs

---

## 5. Runtime Flow

## 5.1 App startup sequence

1. Load environment config.
2. Initialize control-plane DB and secret/session keys.
3. Load all active tenants.
4. Open tenant stores and initialize per-tenant monitor runners.
5. Build HTTP server dependencies.
6. Start runners + HTTP server + periodic housekeeping goroutines.

Key startup logic is in `internal/app/app.go`.

## 5.2 Monitor execution flow

1. Runner loads monitor snapshots.
2. Due monitors are checked by checker map dispatch (`https`, `tcp`, `icmp`, `smtp`, `imap`, `dns`, `udp`, `whois`).
3. Result is stored.
4. State transition is evaluated.
5. Notifications are sent and notification events are persisted.

## 5.3 Remote node flow

1. Agent bootstraps with node ID + bootstrap key.
2. Receives short-lived access token.
3. Polls assigned monitors.
4. Runs checks locally on remote node.
5. Reports results back.
6. Control plane records data and triggers transition notifications.

---

## 6. Data Model and Persistence

## 6.1 Database topology

- `controlplane.db`: tenants, auth providers, local credentials, remote nodes, global settings, audit artifacts.
- `<tenant>.db`: monitors, monitor results, incidents/state, notification endpoints/events, aggregation rollups.

## 6.2 SQLite strategy

- Single connection constraints are intentionally configured (`SetMaxOpenConns(1)`) to avoid SQLite lock contention patterns in-process.
- Startup migrations rely on schema initialization plus additive `ensure*` migration functions.
- Corruption handling includes table readability checks and recreation for known corrupted history tables.

## 6.3 Maintenance jobs

Maintenance includes:

- hourly rollup backfill,
- raw result retention,
- rollup retention,
- monthly `PRAGMA optimize`.

---

## 7. Authentication & Security Architecture

## 7.1 Authentication modes

- Disabled
- Local (username/password per tenant)
- OIDC (global default and/or tenant provider)

## 7.2 Session handling

- Signed cookie (`HMAC-SHA256`) with expiration checks.
- `HttpOnly`, `SameSite=Lax`, optional `Secure` based on base URL scheme.
- Tenant-aware cookie path hardening via slug validation.

## 7.3 OIDC

- State + nonce cookies
- Authorization code exchange
- ID token verification
- Nonce validation
- Dynamic per-tenant OIDC provider cache

## 7.4 TOTP

- RFC-6238 compatible behavior (HMAC-SHA1 by standard)
- ±1 window validation

## 7.5 HTTP security controls

Implemented middleware controls include:

- strict origin/referer validation on mutating requests,
- restrictive CSP,
- `X-Frame-Options: DENY`,
- `X-Content-Type-Options: nosniff`,
- HSTS when HTTPS mode is active,
- lockout windows for local login, admin access, and bootstrap attempts.

---

## 8. Monitoring Engine Details

## 8.1 Supported monitor kinds

- HTTPS / HTTP
- TCP
- ICMP
- SMTP
- IMAP
- DNS
- UDP
- WHOIS

## 8.2 Notable capabilities

- TLS metadata extraction (validity, expiration, remaining days)
- Expected HTTP status code and expected text checks
- Dual-stack network handling in selected checkers
- SMTP/IMAP TLS and STARTTLS paths
- Result + state event persistence and transition-triggered notifications

## 8.3 Execution model

Current runner iteration is sequential per due monitor. This is simple and deterministic, but can delay checks under high monitor count or long timeout scenarios.

---

## 9. Notification System

## 9.1 Email notifier

- Tenant recipient resolution with language preference
- HTML email templates with translated strings
- SMTP transport with configurable TLS modes

## 9.2 Matrix notifier

- Tenant user-level targets
- Per-target delivery attempts with error aggregation

## 9.3 Event recording

Notification success/failure is persisted for observability and postmortem analysis.

---

## 10. Deployment & Operations

## 10.1 Build/runtime

- Go module-based project (`go.mod`)
- Dockerized deployment (compose files, Dockerfile)
- Multi-arch image references in README

## 10.2 Operational strengths

- Minimal external dependencies
- Easy backup model (SQLite files)
- Fast local bootstrap

## 10.3 Operational caveats

- New tenant runner activation currently tied to process startup behavior
- Maintenance execution currently tied to default tenant store context

---

## 11. Code Review Findings

Severity scale: Critical / High / Medium / Low / Info

### 11.1 Medium – Remote node access token authentication scales linearly

**Evidence**

- `internal/store/sqlite/remote_node_store.go` (`AuthenticateRemoteNodeAccessToken`)
- Iterates all enabled token candidates and decrypts each until match.

**Risk**

- O(n) behavior as remote node count grows.
- Potential CPU amplification under repeated unauthorized token attempts.

**Recommendation**

- Store and index a constant-time-comparable token fingerprint (e.g., SHA-256 hash) and lookup directly.
- Keep encrypted token storage if needed, but avoid full-row decrypt scans for authentication.

---

### 11.2 Medium – Multi-tenant maintenance is default-store-centric

**Evidence**

- `internal/app/app.go`: maintenance goroutine starts only when `a.store != nil` and runs against `a.store`.

**Risk**

- Non-default tenant DBs may not receive regular retention/optimization unless covered elsewhere.

**Recommendation**

- Execute maintenance per active tenant store (iterating tenant list with bounded concurrency).
- Add logs per tenant for maintenance outcome.

---

### 11.3 Medium – Runner lifecycle tied to startup snapshot of tenants

**Evidence**

- `internal/app/app.go`: tenants loaded once in startup path (`GetAllTenants`), runners initialized from that list.

**Risk**

- Newly created tenants need process restart to start regular checks.
- Operational friction in dynamic environments.

**Recommendation**

- Add dynamic runner registry with periodic tenant reconciliation or event-driven runner creation/removal.

---

### 11.4 Medium – Sequential due-check execution can produce drift under load

**Evidence**

- `internal/monitor/runner.go`: loops snapshots sequentially, each with timeout-bound check.

**Risk**

- Check latency and schedule drift when many monitors are due simultaneously.

**Recommendation**

- Introduce worker pool (bounded parallelism) with per-tenant queueing.
- Preserve rate limits and avoid DB write bursts by batching or smoothing.

---

### 11.5 Low – WebSocket upgrader globally allows origins, relying on pre-checks

**Evidence**

- `internal/httpserver/server.go`: `dashboardLiveUpgrader.CheckOrigin` returns `true`.
- Handlers call `websocketOriginAllowed` before `Upgrade`.

**Risk**

- Current flow is safe as long as all websocket handlers pre-validate.
- Future handlers could accidentally omit pre-check.

**Recommendation**

- Enforce origin checks in upgrader itself (defense in depth), possibly by injecting server-level checker.

---

### 11.6 Low – Panic usage in route static FS setup

**Evidence**

- `internal/httpserver/server.go`: panics when `fs.Sub` fails.

**Risk**

- Hard crash on startup-time asset embedding mismatch.

**Recommendation**

- Return explicit startup error from constructor rather than panic.

---

### 11.7 Low – Shutdown responsiveness in remote agent loop

**Evidence**

- `internal/remotenode/agent.go`: uses direct `time.Sleep(...)` in run loop.

**Risk**

- Shutdown may wait until sleep completes.

**Recommendation**

- Replace sleep with `select { case <-ctx.Done(): ...; case <-time.After(...): ... }`.

---

### 11.8 Info – Monolithic HTTP server file size impacts maintainability

**Evidence**

- `internal/httpserver/server.go` is very large and combines routing, middleware, view assembly, auth flow, and feature handlers.

**Risk**

- Slower onboarding, larger regression surface, harder isolated testing.

**Recommendation**

- Split by bounded context (auth handlers, dashboard handlers, admin handlers, middleware, websocket module, rendering helpers).

---

### 11.9 Info – Test coverage is narrow relative to feature set

**Evidence**

- `go test ./...` indicates tests mainly in `internal/monitor`, while most packages report `[no test files]`.

**Recommendation**

- Prioritize table-driven unit tests for:
  - auth/session and lockout logic,
  - control-plane store methods,
  - remote node handshake/auth/report paths,
  - critical handler middleware behavior.

---

## 12. Improvement Backlog (Prioritized)

## P0 (next release)

1. Remote access token auth redesign with indexed fingerprint lookup.
2. Multi-tenant maintenance scheduling.
3. Add integration tests for remote node auth/report lifecycle.

## P1

1. Worker pool for monitor execution with bounded concurrency.
2. Dynamic tenant runner reconciliation without restart.
3. Move websocket origin validation into upgrader-level policy.

## P2

1. Refactor giant HTTP server file into cohesive modules.
2. Expand tests around admin/auth/local login lockout and CSRF/origin checks.
3. Introduce benchmark suite for monitor runner and token-auth paths.

---

## 13. Architecture Quality Assessment

## Strengths

- Operationally lightweight and self-hosting friendly.
- Good security baseline (origin checks, secure cookies, lockout mechanisms, encrypted secrets).
- Strong protocol breadth for practical infrastructure monitoring.
- Clear tenant concept with per-tenant DB separation.

## Trade-offs

- Startup-centric orchestration limits dynamic tenant operations.
- Some data-path choices prioritize simplicity over scale (e.g., token auth scan).
- Large handler file weakens long-term maintainability.

## Overall

GoUp is a strong, practical system for self-hosted uptime monitoring. The codebase is production-capable for small/medium setups and already includes thoughtful security and operational controls. Addressing the identified medium findings will significantly improve scalability, maintainability, and resilience with relatively focused engineering effort.

---

## 14. Suggested Documentation Extensions

For future docs, consider adding:

1. Sequence diagrams for:
   - login flows (local/OIDC),
   - monitor check lifecycle,
   - remote node bootstrap/poll/report,
   - notification dispatch.
2. ER diagram for control-plane and tenant DB schemas.
3. SLO/SLA guidance and scaling thresholds.
4. Troubleshooting playbooks for common deployment/runtime issues.
5. Security hardening checklist for reverse proxy and secret management.

---

_End of documentation and review._
