# GoUp Remote Node Agent

This folder documents the **Remote Node Agent** that is part of the same GoUp repository.

## What problem this solves

Some checks must run inside private networks that the main GoUp instance (Control Plane) cannot directly reach.

The Remote Node Agent runs in that internal network, executes assigned monitors (for example internal DNS, APIs, containers), and sends encrypted results back to the Control Plane.

## How the connection to the Control Plane works

The design is intentionally simple and firewall-friendly:

- The Remote Node opens **outbound HTTPS only**.
- The Control Plane never needs to open an inbound connection to the Remote Node.
- Communication is based on a **bootstrap + poll + report** cycle.

### 1) Bootstrap (initial trust)

The agent starts with:

- `REMOTE_NODE_ID`
- `REMOTE_NODE_BOOTSTRAP_KEY`
- `REMOTE_NODE_CONTROL_PLANE_URL` (base URL, for example `https://example.com`)

It authenticates once against the Control Plane bootstrap endpoint and receives a short-lived access token.

### 2) Poll (get work)

At a fixed interval (`REMOTE_NODE_POLL_SECONDS`), the agent calls `/node/poll` using the current access token.

The poll response contains:

- monitor assignments for this node
- token rotation data (new short-lived token)

### 3) Execute + Report (send results)

The agent executes assigned checks locally and sends batched results to `/node/report`.

The Control Plane stores those results in the same internal flows used for local checks:

- results
- states
- incidents
- notifications

## Authentication and transport security

- **TLS is required** for all traffic.
- **mTLS is planned** as an additional hardening step.
- Access tokens are short-lived and rotated regularly (on poll responses).
- Bootstrap keys and tokens are encrypted at rest in the Control Plane database.

### TLS vs. mTLS in one sentence

- TLS: only the server proves its identity.
- mTLS: server and client both present certificates.

## Repository components

- Agent binary: `cmd/remote-node/main.go`
- Agent logic: `internal/remotenode/agent.go`
- Control Plane API + UI: `internal/httpserver/remote_node_handlers.go`, `internal/httpserver/server.go`, `web/templates/dashboard.tmpl`
- Persistence: `internal/store/sqlite/remote_node_store.go` and monitor executor fields in the tenant DB

## Quick start

1. In the tenant dashboard (admin), create a Remote Node.
2. Copy the generated values:
   - `REMOTE_NODE_ID`
   - `REMOTE_NODE_BOOTSTRAP_KEY`
   - `REMOTE_NODE_CONTROL_PLANE_URL` as the **base URL** of your GoUp instance (for example `https://example.com`, not `.../node/bootstrap`)
3. Start the container with these environment variables.

Example:

- `GOUP_MODE=remote-node`
- `REMOTE_NODE_CONTROL_PLANE_URL=https://example.com`
- `REMOTE_NODE_ID=rn_xxx`
- `REMOTE_NODE_BOOTSTRAP_KEY=...`
- `REMOTE_NODE_POLL_SECONDS=20`

Important:

- The container image includes both server and agent.
- By default it starts the regular GoUp server.
- Set `GOUP_MODE=remote-node` to run the agent.

If `.../node/bootstrap` is configured by mistake, the agent normalizes it to the base URL automatically.

For ICMP monitors, the container also needs `NET_RAW` (Compose: `cap_add: [NET_RAW]`).

## Monitor assignment

When at least one Remote Node exists, the monitor form shows an **Execution** field:

- Control Plane (local)
- Remote: `<node_id>`

Only monitors with executor `remote:<node_id>` are executed by that agent.

## Heartbeat and offline status

- `last_seen_at` is updated on poll/report.
- The UI shows ONLINE/OFFLINE based on configured heartbeat timeout.
- This status can be used for inactivity alerting.

## Bootstrap key rotation

- You can rotate the bootstrap key per node in the tenant dashboard.
- After rotation, only the new key can bootstrap future sessions.
- Already running nodes with valid access tokens continue until re-bootstrap is needed.
