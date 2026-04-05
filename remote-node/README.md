# GoUp Remote-Node-Agent

Dieser Unterordner dokumentiert den **Remote-Node-Agent im selben Repo**.

## Ziel

Eine kleine interne Node führt Checks in nicht erreichbaren Netzen aus (z. B. interne DNS/API/Container) und reportet die Ergebnisse verschlüsselt an die Control-Plane.

## Architektur (Push + Poll)

- **Nur Outbound HTTPS** von der Remote-Node zur Control-Plane.
- **Bootstrap** mit `REMOTE_NODE_ID` + einmaligem `REMOTE_NODE_BOOTSTRAP_KEY`.
- Danach **kurzlebige Access-Tokens** (Rotation bei jedem Poll-Response).
- Remote-Node ruft regelmäßig Provisioning ab (`/node/poll`).
- Remote-Node führt zugewiesene Monitore aus und sendet gebündelte Ergebnisse (`/node/report`).
- Control-Plane schreibt Ergebnisse in dieselben Tabellen/Flows wie lokale Checks (Resultate, States, Incidents, Notifications).

## mTLS vs. TLS (kurz)

- **TLS (normal):** nur der Server weist sich mit Zertifikat aus.
- **mTLS:** zusätzlich muss der Client ein Zertifikat vorweisen.
- Vorteil mTLS: deutlich stärkere Client-Authentifizierung auf Transportebene.
- Nachteil: höherer Betriebsaufwand (PKI, Zertifikat-Rotation, Revocation).

Aktuell ist TLS Pflicht, mTLS ist als optionaler nächster Schritt vorgesehen.

## Komponenten im Repo

- Agent-Binary: cmd/remote-node/main.go
- Agent-Logik: internal/remotenode/agent.go
- Control-Plane-API + Tenant-UI: internal/httpserver/remote_node_handlers.go, internal/httpserver/server.go, web/templates/dashboard.tmpl
- Persistenz: internal/store/sqlite/remote_node_store.go + Monitor-Executor-Felder in Tenant-DB

## Schnellstart

1. Im Tenant-Dashboard als Admin eine Remote-Node anlegen.
2. Aus der Notice kopieren:
   - `REMOTE_NODE_ID`
   - `REMOTE_NODE_BOOTSTRAP_KEY`
   - `REMOTE_NODE_CONTROL_PLANE_URL` als Basis-URL der GoUp-Instanz (`https://example.com`, nicht `.../node/bootstrap`)
3. Agent-Container mit Env starten.

Beispiel-Variablen:

- `GOUP_MODE=remote-node`
- `REMOTE_NODE_CONTROL_PLANE_URL=https://example.com`
- `REMOTE_NODE_ID=rn_xxx`
- `REMOTE_NODE_BOOTSTRAP_KEY=...`
- `REMOTE_NODE_POLL_SECONDS=20`

Wichtig: Das Container-Image enthält **Server und Agent**. Standardmäßig startet es den normalen GoUp-Server. Für eine Remote-Node muss daher `GOUP_MODE=remote-node` gesetzt sein.

Falls versehentlich doch `.../node/bootstrap` eingetragen wird, normalisiert der Agent das jetzt automatisch auf die Basis-URL.

## Monitor-Zuweisung

Wenn mindestens eine Remote-Node existiert, erscheint im Monitor-Dialog ein Feld **Ausführung**:

- Control-Plane (lokal)
- Remote: `<node_id>`

Nur Monitore mit Executor `remote:<node_id>` werden vom Agent ausgeführt.

## Heartbeat/Offline

- `last_seen_at` wird bei Poll/Report aktualisiert.
- UI zeigt ONLINE/OFFLINE anhand des konfigurierten Heartbeat-Timeouts.
- Bei längerer Inaktivität kann darauf Benachrichtigung aufgebaut werden (Status bereits im Datenmodell vorhanden).

## Sicherheit

- Bootstrap-Key und Access-Token werden verschlüsselt in der Control-Plane-DB gespeichert (gleiches Secret-Handling wie andere Secrets).
- Access-Tokens sind kurzlebig und werden regelmäßig rotiert.
- Kommunikation ausschließlich über HTTPS.

## Bootstrap-Key Rotation

- Im Tenant-Dashboard kann pro Remote-Node der **Bootstrap-Key rotiert** werden.
- Nach Rotation gilt nur noch der neue Key für zukünftige Bootstrap-Vorgänge.
- Bereits laufende Nodes mit gültigem Access-Token laufen weiter; spätestens bei Re-Bootstrap muss der neue Key gesetzt sein.
