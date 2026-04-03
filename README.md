# GoUp

GoUp ist ein ultraleichtes, self-hosted Uptime-Monitoring-System für kleine VPS-Instanzen. Das Ziel ist ein einzelner, ressourcenschonender Go-Dienst mit serverseitiger WebUI, SQLite als Standard-Storage und Docker-first Deployment.

## Architekturentscheidung

**Entscheidung: Go statt Rust**

Go ist für dieses Projekt die pragmatischere Wahl:

- sehr geringe Laufzeitkosten bei lang laufenden Netzwerkdiensten
- exzellente Standardbibliothek für HTTP, TLS, SMTP, IMAP-nahe TCP/TLS-Prüfungen und Scheduler-Logik
- einfache Cross-Compilation und schlanke Docker-Builds
- geringere Implementierungs- und Wartungskomplexität als Rust für ein kleines Admin-System
- ausreichend performant für hunderte Checks auf einem Mini-VPS

Rust wäre nur dann klar überlegen, wenn maximale Speichereffizienz bis ins letzte Detail oder sehr stark parallelisierte High-Scale-Workloads im Vordergrund stünden. Für dieses Zielprofil gewinnt Go bei Time-to-Maintain, Einfachheit und Betriebsstabilität.

## MVP-Zielbild

Ein einzelner Dienst übernimmt:

- HTTP-Server für Admin-WebUI
- OIDC-Login gegen Authentik
- Scheduler und Check-Ausführung im selben Prozess
- SQLite-Zugriff
- Matrix-Benachrichtigungen
- einfache Status- und Admin-Seiten per Server-Side Rendering

## Technische Leitplanken

- **Hauptsprache:** Go
- **Datenbank:** SQLite via Pure-Go-Treiber
- **Frontend:** serverseitige Templates, kein schweres SPA
- **Deployment:** ein Docker-Container, ein persistentes Datenverzeichnis
- **Konfiguration:** Basiskonfiguration per Env, betriebliche Einstellungen später primär per WebUI
- **Auth:** OIDC mit Authentik
- **Benachrichtigungen:** Matrix per Client-Server API

## Vorgeschlagene Libraries

- `net/http`, `html/template`, `crypto/tls`, `database/sql` aus der Standardbibliothek
- `modernc.org/sqlite` für SQLite ohne CGO
- `github.com/coreos/go-oidc/v3/oidc` für OIDC Discovery und ID-Token-Verifikation
- `golang.org/x/oauth2` für Authorization Code Flow

Matrix wird bewusst zunächst über die HTTP-API angebunden statt über ein schweres SDK.

## Projektstruktur

- `cmd/goup` – Startpunkt
- `internal/app` – Verdrahtung des Gesamtsystems
- `internal/config` – Konfiguration aus Env/Defaults
- `internal/auth` – OIDC- und Session-Logik
- `internal/httpserver` – Router, Handler, Middleware
- `internal/store/sqlite` – SQLite-Initialisierung und Abfragen
- `internal/monitor` – Check-Modelle und Scheduler-nahe Domänenlogik
- `web` – Templates und statische Assets
- `docs` – Architektur und Datenmodell

## Phasen

### Phase 1: MVP

Enthalten:

- Docker-first Einzelcontainer
- Admin-WebUI mit OIDC-Login
- SQLite-Storage
- CRUD-Grundlage für Monitore und Notification-Ziele
- HTTP/HTTPS-Monitoring mit Zertifikatsauswertung
- TCP-Port-Monitoring
- ICMP-Monitoring
- SMTP- und IMAP-Checks inkl. TLS/STARTTLS-Zertifikatsprüfung
- Matrix-Benachrichtigungen bei Statuswechseln
- Scheduler, Healthcheck, Logging, Basis-Backup-Story für SQLite-Datei

Risiken/Komplexität:

- ICMP braucht je nach Container-/Host-Setup zusätzliche Capabilities
- SMTP/IMAP-STARTTLS muss robust gegen Server-Besonderheiten implementiert werden
- OIDC-Session-Handling muss minimalistisch, aber sauber signiert sein

### Phase 2: Produktionsreife Kernfunktionen

Enthalten:

- Retry-/Debounce-Logik gegen Alarmflattern
- Wartungsfenster und Pause-Funktion
- feinere Rollen-/Rechteprüfung
- historische Uptime-Aggregation
- Export/Import von Konfiguration
- Backup-/Restore-Hilfen
- Public Status Page als read-only Modul

Risiken/Komplexität:

- Datenmodell für Events, Aggregationen und Incidents bleibt bewusst einfach, darf aber Reporting nicht blockieren
- Public Status Page braucht saubere Trennung von internem Admin-Kontext und öffentlicher Sicht

### Phase 3: Komfortfunktionen

Enthalten:

- Mehrere Notification-Kanäle
- Tagging, Filter, Gruppen
- kleine API für Automatisierung
- Status-Badges, RSS/Webhooks
- UI-Verbesserungen, Bulk-Operationen

Risiken/Komplexität:

- Feature-Bloat vermeiden
- Komplexität nur einführen, wenn Betrieb und RAM-Fußabdruck im Rahmen bleiben

## API-/UI-Grundkonzept

- Admin-Oberfläche serverseitig gerendert
- klassische HTML-Formulare statt schwerem SPA-Frontend
- später optional kleine JSON-Endpunkte für progressive Verbesserungen
- Public Status Page von Anfang an architektonisch berücksichtigt, aber nicht Teil des initialen Funktionsumfangs

## Datenmodell

Das detaillierte Datenmodell steht in [docs/architecture.md](docs/architecture.md).

## Schnellstart

```bash
docker compose up --build
```

Dann:

- App unter `http://localhost:8080`
- Healthcheck unter `http://localhost:8080/healthz`

OIDC ist im Scaffold optional abschaltbar, damit die lokale Entwicklung ohne Identity Provider möglich bleibt.
