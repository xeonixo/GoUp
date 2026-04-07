# GoUp – Umfangreiche Code Review

**Datum:** 07.04.2026  
**Repository:** GoUp  
**Review-Art:** First-pass Architektur-, Security-, Runtime- und Maintainability-Review

---

## 1) Scope und Vorgehen

Diese Review basiert auf direkter Analyse des Go-Quellcodes (ohne Berücksichtigung anderer `.md`-Dateien) mit Fokus auf:

- Bootstrapping / Lifecycle
- HTTP-Server, Middleware, Auth-Flows
- Remote-Node-Protokoll (Bootstrap / Poll / Report)
- Store- und Multi-Tenant-Verhalten (SQLite)
- Monitoring-Runner, Notifier, Betriebsrisiken
- Security- und Zuverlässigkeitsrisiken

Zusätzlich wurden Qualitätschecks ausgeführt:

- `go vet ./...` → **ohne Befund** (laut aktueller Terminal-Historie)
- `go test ./...` → **Tests laufen durch**, aber fast alle Pakete ohne Testdateien

---

## 2) Executive Summary

Der Code ist insgesamt pragmatisch, produktionsnah und für self-hosted Szenarien gut strukturiert. Besonders positiv sind:

- starke Security-Baselines (HMAC-Sessions, Security-Header, Origin/Referer-Checks, Lockout-Mechanismen),
- gute Trennung zwischen Control-Plane und Tenant-Datenbanken,
- solide Remote-Node-Integration mit kurzlebigen Access-Tokens,
- defensive Nutzung von `context.WithTimeout(...)` in kritischen Pfaden.

**Wichtigste Risiken / Verbesserungspotentiale:**

1. **Skalierungsproblem bei Remote-Node-Token-Authentifizierung** (lineare Kandidatensuche + Entschlüsselung pro Request).
2. **Tenant-Runner/Store-Lifecycle-Risiko** (zusätzliche DB-Handles für Runner, potenziell nicht sauber geschlossen).
3. **Fehlende Request-Body-Limits auf Node-Endpunkten** (`/node/bootstrap`, `/node/poll`, `/node/report`) mit DoS-Potenzial.
4. **Multi-Tenant-Wartung und Runner-Lifecycle sind startup-zentriert** (kein dynamisches Reconcile zur Laufzeit).
5. **Sehr große Server-Datei** erschwert Testbarkeit und sichere Weiterentwicklung.

---

## 3) Stärken (Positive Findings)

## 3.1 Security-Baseline ist überdurchschnittlich solide

- Signierte Sessions via HMAC-SHA256 inkl. Ablaufprüfung.
- Cookie-Pfade sind tenant-sicher normalisiert.
- Origin/Referer-Schutz für mutierende Requests.
- Strikte Security-Header inkl. CSP, X-Frame-Options, HSTS (bei HTTPS).
- Lockout-Mechanismen für lokale Logins, Admin-Zugriff und Node-Bootstrap.
- Secrets im Control-Plane-Store via AES-GCM verschlüsselt.
- Timing-safe Vergleiche für sensible Token-/Secret-Prüfungen.

## 3.2 Architektur passt gut zu Self-Hosted-Betrieb

- SQLite + geringe Betriebsabhängigkeiten.
- Saubere Trennung zwischen App- und Control-Plane-Store.
- Remote-Node-Protokoll ist funktional vollständig (Bootstrap/Poll/Report + Event-Tracking).

## 3.3 Defensive Laufzeitmuster

- Kontextgebundene Timeouts in Runnern und Notifiern.
- Healthcheck vorhanden.
- Graceful Shutdown im HTTP-Server integriert.

---

## 4) Detaillierte Findings

Severity-Skala: **High / Medium / Low / Info**

## 4.1 High – Remote-Node Access-Token-Authentifizierung skaliert linear

**Evidence**

- `internal/store/sqlite/remote_node_store.go` in `AuthenticateRemoteNodeAccessToken(...)`:
  - lädt alle gültigen Kandidaten,
  - entschlüsselt je Datensatz den Token,
  - vergleicht dann im Loop.

**Risiko**

- O(n) pro Poll/Report-Request; bei wachsender Node-Zahl steigen CPU- und DB-Kosten deutlich.
- Führt unter Last schneller zu Latenzspitzen auf zentralen Endpunkten.

**Empfehlung**

- Token-Fingerprint speichern (z. B. `sha256(token)`), indexieren und direkt per Lookup authentifizieren.
- Ciphertext nur noch für ggf. zusätzliche Checks/Rotation nutzen.

---

## 4.2 High – Runner-/Store-Lifecycle für Non-Default-Tenants ist riskant

**Evidence**

- `internal/app/app.go`:
  - Runner werden je aktivem Tenant erstellt.
  - Für Non-Default-Tenants wird im Runner-Aufbau ein eigener Store geöffnet.
- `internal/store/sqlite/tenant_store_manager.go`:
  - verwaltet eigene Store-Instanzen separat.
- Es gibt keinen expliziten `Close()`-Pfad für die nur im Runner erzeugten Non-Default-Stores.

**Risiko**

- Potenzieller Handle-/Ressourcen-Leak.
- Doppeltes Öffnen derselben Tenant-DB in verschiedenen Komponenten erhöht Komplexität/Lock-Contention.

**Empfehlung**

- Einheitliche Store-Inhaberschaft einführen:
  - entweder Runner immer Stores aus `TenantStoreManager` beziehen,
  - oder dediziertes Runner-Store-Registry mit sauberem `Close()` beim App-Shutdown.
- Lifecycle explizit dokumentieren und mit Tests absichern.

---

## 4.3 High – Node-Endpunkte ohne Request-Body-Limits

**Evidence**

- `internal/httpserver/remote_node_handlers.go`:
  - JSON-Decode in `handleRemoteNodeBootstrap`, `handleRemoteNodePoll`, `handleRemoteNodeReport` direkt auf `r.Body`.
  - Kein `http.MaxBytesReader(...)`.

**Risiko**

- Speicher-/CPU-Druck durch übergroße Bodies (DoS-Vektor), insbesondere auf zentralen Endpunkten.

**Empfehlung**

- Strikte Body-Limits pro Endpoint setzen (z. B. Bootstrap/Poll klein, Report moderat begrenzt).
- Zusätzlich `Decoder.DisallowUnknownFields()` für härteres Input-Contracting.

---

## 4.4 Medium – Wartungsjobs laufen nur gegen Default-Tenant-Store

**Evidence**

- `internal/app/app.go`:
  - `runMaintenance()` verwendet `a.store` (Default-Store).
  - Keine Iteration über alle aktiven Tenant-Stores.

**Risiko**

- Retention/Optimierung/Backfill werden in Multi-Tenant-Szenarien für Non-Default-Tenants ggf. nicht regelmäßig ausgeführt.

**Empfehlung**

- Tenant-übergreifenden Wartungs-Dispatcher implementieren.
- Ausführung + Ergebnis pro Tenant loggen/monitoren.

---

## 4.5 Medium – Runner-Lifecycle ist startup-zentriert (kein Reconcile)

**Evidence**

- `internal/app/app.go`:
  - Runner werden in `New(...)` aus initialem Tenant-Snapshot aufgebaut.
  - Keine laufende Synchronisation bei Tenant-Aktivierung/Deaktivierung zur Laufzeit.

**Risiko**

- Konfigurationsänderungen wirken erst nach Neustart vollständig.

**Empfehlung**

- Reconcile-Loop einführen: Delta-Erkennung + Runner start/stop per Tenant.

---

## 4.6 Medium – Sequenzielle Due-Checks können unter Last driften

**Evidence**

- `internal/monitor/runner.go`:
  - `runDueChecks()` iteriert fällige Monitore sequenziell.

**Risiko**

- Bei vielen fälligen Checks oder langen Timeouts verschiebt sich der effektive Check-Zeitplan.

**Empfehlung**

- Bounded Worker-Pool (tenant-lokal) einführen.
- Parallelität begrenzen, um DB-Write-Spitzen zu kontrollieren.

---

## 4.7 Medium – Remote-Agent reagiert verzögert auf Shutdown

**Evidence**

- `internal/remotenode/agent.go` in `Run(...)`:
  - nutzt `time.Sleep(...)` statt kontextsensitivem Warten.

**Risiko**

- Shutdown-Latenz bis zur Poll-Intervalllänge.

**Empfehlung**

- `select { case <-ctx.Done(): ...; case <-time.After(...) }` einsetzen.

---

## 4.8 Medium – WebSocket-Upgrader akzeptiert global alle Origins

**Evidence**

- `internal/httpserver/server.go`:
  - `dashboardLiveUpgrader.CheckOrigin` gibt immer `true` zurück.
  - Zusätzliche Prüfung erfolgt vorher über `websocketOriginAllowed(...)`.

**Risiko**

- Aktuell funktional ok, aber fragil: neue WebSocket-Handler könnten die Vorprüfung vergessen.

**Empfehlung**

- Origin-Validierung direkt im Upgrader erzwingen (Defense in Depth).

---

## 4.9 Medium – In-Memory Lockout-Maps ohne echte Garbage Collection

**Evidence**

- `internal/httpserver/server.go`:
  - `localLoginAttempts`, `adminAccessAttempts`, `bootstrapAttempts` als In-Memory-Maps.
  - Alte Einträge werden nur bei erneuter Interaktion desselben Keys bereinigt.

**Risiko**

- Langfristiges Wachstum bei vielen einmaligen Schlüsseln/IPs.

**Empfehlung**

- Periodischen Sweeper einführen oder TTL-Cache verwenden.

---

## 4.10 Low – `panic(...)` in `routes()` bei FS-Subfehlern

**Evidence**

- `internal/httpserver/server.go` in `routes()`:
  - `fs.Sub(...)` Fehler führen zu `panic`.

**Risiko**

- Harte Prozessbeendigung statt kontrolliertem Startup-Fehler.

**Empfehlung**

- Fehler bis `New(...)` propagieren und dort kontrolliert behandeln.

---

## 4.11 Low – Password-Reset-Token ist stateless und wiederverwendbar bis Ablauf

**Evidence**

- `internal/httpserver/server.go`:
  - signierter Token mit Nonce + Expiry, aber ohne serverseitige Einmalverwendung/Revocation.

**Risiko**

- Bei Token-Leak ist Replay bis Ablauf möglich.

**Empfehlung**

- Optional jti/store-basiertes One-Time-Use einführen.

---

## 4.12 Low – HTTP-Request-Logging ohne Statuscode

**Evidence**

- `internal/httpserver/server.go` in `logging(...)`:
  - loggt Method, Path, Duration, aber keinen Response-Status.

**Risiko**

- Erschwerte Incident-Analyse und SLO-Auswertung.

**Empfehlung**

- ResponseWriter wrappen und Status/Bytes mitloggen.

---

## 4.13 Info – Testabdeckung ist aktuell zu schmal

**Evidence**

- `go test ./...` zeigt nur im Monitor-Paket Tests; die meisten Pakete haben `[no test files]`.

**Risiko**

- Kritische Flows (Auth, Control-Plane, Remote-Node, HTTP-Middleware) sind regressionsanfällig.

**Empfehlung**

- Priorisierte Teststrategie:
  1) Auth/session/lockout,
  2) Remote-Node bootstrap/auth/report,
  3) TenantStoreManager/Lifecycle,
  4) Control-Plane Security-Funktionen,
  5) Handler-Middleware (Origin, AuthZ).

---

## 5) Sicherheits- und Implementierungsrisiken (kompakt)

- **Skalierungsrisiko:** Token-Auth O(n) + Sequenzieller Runner.
- **Betriebsrisiko:** Multi-Tenant-Maintenance und Runner-Lifecycle nicht dynamisch.
- **Verfügbarkeitsrisiko:** fehlende Body-Limits an externen Node-Endpunkten.
- **Wartbarkeitsrisiko:** monolithischer Server-File-Umfang.
- **Test-Risiko:** zu wenig automatisierte Absicherung außerhalb `internal/monitor`.

---

## 6) Priorisierte Verbesserungs-Roadmap

## P0 (nächster Zyklus)

1. Remote-Token-Auth auf indexierten Fingerprint-Lookup umstellen.
2. Body-Limits + `DisallowUnknownFields` auf allen `/node/*` Endpunkten.
3. Store-/Runner-Lifecycle konsolidieren und sauberes Shutdown-Close sicherstellen.
4. Multi-Tenant-Maintenance für alle aktiven Tenant-Stores ausführen.

## P1

1. Dynamisches Runner-Reconcile für Tenant-Änderungen.
2. Worker-Pool für Due-Checks mit begrenzter Parallelität.
3. WebSocket-Origin-Check zusätzlich im Upgrader erzwingen.

## P2

1. `internal/httpserver/server.go` in fachliche Module schneiden.
2. Lockout-Map-Sweeper/TTL-Cache implementieren.
3. Logging um Statuscode/Response-Bytes erweitern.
4. Password-Reset optional auf One-Time-Token umstellen.

---

## 7) Fazit

GoUp ist bereits auf einem guten technischen Fundament und zeigt viele korrekte Sicherheitsentscheidungen. Die größten Hebel liegen nicht in „Bugfixing“, sondern in **Skalierbarkeit, Lifecycle-Klarheit und Testabdeckung**. Wenn die P0-Maßnahmen umgesetzt werden, sinkt das operative Risiko signifikant und das System wird robust für größere Multi-Tenant-Installationen.

---

## 8) Umgesetzte P0-Maßnahmen (07.04.2026)

Die folgenden P0-Punkte wurden umgesetzt.

### 8.1 P0-1: Remote-Token-Auth auf Fingerprint-Lookup umgestellt

**Implementierung**

- `remote_nodes` erweitert um `access_token_fingerprint`.
- Index eingeführt: `idx_remote_nodes_access_token_fingerprint` auf `(access_token_fingerprint, enabled, access_token_expires_at)`.
- `IssueRemoteNodeAccessToken(...)` speichert jetzt zusätzlich `sha256(token)` als Fingerprint.
- `AuthenticateRemoteNodeAccessToken(...)` macht jetzt einen direkten DB-Lookup über Fingerprint statt linearer Vollscan über alle Kandidaten.
- Migration/Kompatibilität:
  - Column wird bei Bestandssystemen per `ALTER TABLE` ergänzt.
  - Bestehende aktive Tokens werden per Backfill entschlüsselt, gehasht und mit Fingerprint nachgezogen.

**Effekt**

- Auth-Pfad auf `/node/poll` und `/node/report` skaliert jetzt über indexierten Lookup statt O(n)-Kandidatensuche.

### 8.2 P0-2: Request-Body-Limits + striktes JSON-Contracting auf allen `/node/*` Endpunkten

**Implementierung**

- Neue strikte JSON-Decode-Hilfe mit:
  - `http.MaxBytesReader(...)`,
  - `Decoder.DisallowUnknownFields()`,
  - Reject bei mehreren JSON-Dokumenten im Body.
- Limits eingeführt:
  - `/node/bootstrap`: 4 KiB,
  - `/node/poll`: 4 KiB,
  - `/node/report`: 512 KiB.
- `handleRemoteNodeBootstrap`, `handleRemoteNodePoll`, `handleRemoteNodeReport` nutzen jetzt den strikten Decoder.

**Effekt**

- Deutlich reduziertes DoS-Risiko durch große Bodies.
- Stärkeres Input-Contracting gegen unerwartete Felder.

### 8.3 P0-3: Store-/Runner-Lifecycle konsolidiert

**Implementierung**

- Runner beziehen Tenant-Stores jetzt einheitlich über `TenantStoreManager.StoreForTenant(...)`.
- Direkte zusätzliche `store.Open(...)`-Aufrufe für Non-Default-Tenants im Runner-Aufbau wurden entfernt.
- Fehlerpfade schließen keine manager-owned Stores mehr ad hoc.

**Effekt**

- Klare Store-Inhaberschaft (Manager).
- Kein zusätzlicher Runner-spezifischer Store-Handle-Lifecycle außerhalb des Managers.
- Shutdown bleibt konsistent über `TenantStoreManager.Close()`.

### 8.4 P0-4: Multi-Tenant-Maintenance für alle aktiven Tenants

**Implementierung**

- `runMaintenanceOnce(...)` läuft jetzt tenant-übergreifend:
  - lädt alle Tenants aus der Control-Plane,
  - filtert aktive Tenants mit App-DB,
  - führt `RunMaintenance(...)` je Tenant-Store aus.
- Logging wurde tenant-spezifisch erweitert.

**Effekt**

- Wartung/Retention/Optimierung läuft jetzt auch für Non-Default-Tenants regelmäßig mit.

### 8.5 Verifikation

- `go test ./...` erfolgreich.

---

## 9) Umgesetzte P1-Maßnahmen (07.04.2026)

Die folgenden P1-Punkte wurden umgesetzt.

### 9.1 P1-1: Dynamisches Runner-Reconcile für Tenant-Änderungen

**Implementierung**

- Runner-Verwaltung in `internal/app/app.go` von statischer Liste auf tenantbezogene Registry umgestellt (`map[tenant_id]*tenantRunner`).
- Reconcile-Loop ergänzt (`runRunnerReconcile(...)`, Intervall 30s):
  - lädt Tenants aus der Control-Plane,
  - berechnet Sollzustand (aktive Tenants mit App-DB),
  - stoppt Runner bei deaktivierten/entfernten Tenants,
  - startet Runner für neue Tenants,
  - startet Runner neu bei relevanten Tenant-Konfigurationsänderungen (z. B. `slug`, `db_path`).
- Einheitlicher Runner-Aufbau zentralisiert über `buildTenantRunner(...)`.
- Runner werden mit tenant-spezifischem `context.WithCancel(...)` gestartet und sauber gestoppt.

**Effekt**

- Tenant-Aktivierung/Deaktivierung und relevante Konfigänderungen werden ohne kompletten App-Neustart wirksam.

### 9.2 P1-2: Bounded Worker-Pool für Due-Checks

**Implementierung**

- `internal/monitor/runner.go`:
  - Due-Snapshots werden zunächst gesammelt.
  - Abarbeitung erfolgt über begrenzte Parallelität (`workers = 4`, semaphore-basiert).
  - Einzel-Check-Logik in `runSnapshot(...)` extrahiert.
- Tick-Zyklus bleibt deterministisch, da ein Lauf auf Abschluss aller Worker wartet.

**Effekt**

- Weniger Schedule-Drift bei vielen fälligen Checks.
- Kontrollierte Parallelität statt rein sequentieller Ausführung.

### 9.3 P1-3: WebSocket-Origin-Check im Upgrader erzwingen

**Implementierung**

- Globaler Upgrader mit `CheckOrigin: true`-Default entfernt.
- Neuer servergebundener Upgrader `dashboardLiveUpgrader()` setzt `CheckOrigin` explizit auf `s.websocketOriginAllowed`.
- Beide Live-WebSocket-Endpunkte nutzen jetzt den servergebundenen Upgrader.

**Effekt**

- Defense-in-Depth verbessert: Origin-Validierung ist direkt im Upgrade-Pfad verankert, nicht nur als vorgelagerte Handler-Prüfung.

### 9.4 Verifikation

- `go test ./...` erfolgreich.
- `go vet ./...` ohne Befund.
