# GoUp

GoUp ist ein leichtgewichtiges, self-hosted Uptime-Monitoring für kleine bis mittlere Umgebungen.

Ziele:

- **ein einzelner Go-Prozess** statt verteilter Mikroservices
- **SQLite-first** mit minimalem Betriebsaufwand
- **Server-Side UI** ohne schweres SPA
- **Docker-first Deployment**

---

## Features (aktueller Stand)

- Multi-Tenant-fähige Web-UI
- Monitor-Typen:
	- `https`
	- `tcp`
	- `icmp`
	- `smtp` (`tls` / `starttls`)
	- `imap` (`tls` / `starttls`)
	- `dovecot`
- Zertifikatsauswertung inkl. Restlaufzeit
- Incident-/Status-Tracking und Notification-Events
- Matrix-Benachrichtigungen bei Statuswechseln
- E-Mail-Benachrichtigungen bei Statuswechseln (via globalem SMTP)
- Admin-Bereich für:
	- Tenants
	- Auth-Provider (OIDC / Local)
	- lokale Benutzer
	- globale SMTP-Einstellungen
- Persistentes Audit-Log für Admin-Aktionen
- Password-Reset für lokale Benutzer (über SMTP)

---

## Architektur auf einen Blick

GoUp läuft als ein Dienst und bündelt:

- HTTP-Server + SSR Templates
- Auth-Handling (OIDC / Local / Disabled)
- Scheduler + Monitor-Runner
- SQLite-Storage
- Notification-Dispatch

### Datenhaltung

Es gibt zwei SQLite-Bereiche:

1. **Control Plane DB** (z. B. `controlplane.db`)
	 - Tenants, Auth-Provider, lokale Credentials, Admin-Audit, globale SMTP-Settings
2. **Tenant DB** (z. B. `goup.db` bzw. tenant-spezifische DB-Dateien)
	 - Monitore, Resultate, Incidents, Notification-Events

Details: [docs/architecture.md](docs/architecture.md)

---

## Schnellstart (Docker)

### 1) Konfiguration anlegen

```bash
cp .env.example .env
```

Für lokalen Start reicht standardmäßig `GOUP_AUTH_MODE=disabled`.

### 2) Starten

```bash
docker compose up -d --build
```

### 3) Prüfen

- App: http://localhost:8080
- Healthcheck: http://localhost:8080/healthz

Stoppen:

```bash
docker compose down
```

---

## Lokale Entwicklung (ohne Docker)

Voraussetzungen:

- Go 1.22+

Start:

```bash
go run ./cmd/goup
```

Tests:

```bash
go test ./...
```

---

## Konfiguration (Environment)

Wichtige Variablen:

- `GOUP_ADDR` – Bind-Adresse, z. B. `:8080`
- `GOUP_BASE_URL` – öffentliche Basis-URL, z. B. `https://monitor.example.com`
- `GOUP_DATA_DIR` – Datenverzeichnis
- `GOUP_DB_PATH` – Default Tenant DB
- `GOUP_CONTROL_DB_PATH` – Control Plane DB (optional, Standard: `$GOUP_DATA_DIR/controlplane.db`)
- `GOUP_LOG_LEVEL` – `debug|info|warn|error`
- `GOUP_SESSION_KEY` – **Pflicht für produktiv**, min. 16 Zeichen
- `GOUP_SSO_SECRET_KEY` – Schlüssel für verschlüsselte Provider-Secrets (stark empfohlen)
- `GOUP_CONTROL_PLANE_ADMIN_KEY` – separater Zugriffsschlüssel für `/app/admin/*` (unabhängig von Tenant-Rollen)

Auth:

- `GOUP_AUTH_MODE` – `disabled`, `local`, `oidc`

OIDC wird tenant-basiert über den Admin-Bereich konfiguriert (`Provider` je Tenant). Eine globale OIDC-Konfiguration über `.env` ist nicht erforderlich.

E-Mail-Notifications:

- Automatisch: E-Mail-Adressen der Benutzer-Mitgliedschaften im jeweiligen Tenant
- `GOUP_NOTIFY_EMAIL_TO` – optional zusätzliche Komma-separierte Empfänger, z. B. `ops@example.com,oncall@example.com`
- `GOUP_NOTIFY_EMAIL_SUBJECT_PREFIX` – optionales Subject-Präfix

> Hinweis: Für gemischte Login-Methoden (Local + OIDC) pro Tenant kann `GOUP_AUTH_MODE=local` genutzt werden.

---

## Auth-Modi

### `disabled`

- Kein Login erforderlich
- Gut für lokale Entwicklung
- **Nicht** für produktive öffentliche Deployments

### `oidc`

- Login via OIDC
- Tenant-spezifische Provider möglich
- Bootstrap-Mechanismus: Der **erste erfolgreiche OIDC-Login** wird automatisch als `Super-Admin` angelegt (wenn noch kein Super-Admin existiert)
- Weitere OIDC-Benutzer werden nicht automatisch zu Super-Admins

### `local`

- Lokale Benutzeranmeldung je Tenant
- Login über `/{tenantSlug}` (bzw. `/{tenantSlug}/login`)
- Optionaler Password-Reset via SMTP

### Control-Plane Zugriff (strikt getrennt)

- Der Bereich `/app/admin/*` nutzt einen **eigenen Access-Mechanismus** über `GOUP_CONTROL_PLANE_ADMIN_KEY`.
- Tenant-User (auch `admin` oder global markierte Nutzer) erhalten dadurch **keinen** direkten Verwaltungszugriff auf Tenants/Provider.
- Einstieg: `/app/admin/access` (Key eingeben), danach wird eine separate Control-Plane-Session gesetzt.

---

## Wichtige UI-Routen

- Dashboard: `/app/`
- Admin-Dashboard: `/app/admin/`
- Tenants: `/app/admin/tenants`
- Tenant Login: `/{tenantSlug}/login`
- Health: `/healthz`

---

## Monitor-Ziel-Formate

- `https`: vollständige URL, z. B. `https://example.com/health`
- `tcp`: `host:port`
- `icmp`: Hostname oder IP
- `smtp`, `imap`, `dovecot`: `host:port`

TLS-Verhalten:

- `https` nutzt TLS
- Mail-Protokolle unterstützen `tls` und `starttls`

---

## Betriebshinweise

### ICMP in Containern

Für ICMP braucht der Container i. d. R. `NET_RAW`.
Das ist in der Compose-Datei bereits berücksichtigt.

### Reverse Proxy / CSRF / Origin-Checks

GoUp prüft bei schreibenden Requests `Origin`/`Referer` gegen `GOUP_BASE_URL`.
Wenn hinter Proxy betrieben:

- `GOUP_BASE_URL` auf die externe URL setzen
- konsistente Hostnamen nutzen

### Backups

Mindestens sichern:

- Control Plane DB
- alle Tenant-DB-Dateien im Datenverzeichnis

Empfehlung:

- regelmäßige Dateibackups (inkl. `-wal` / `-shm`, falls vorhanden)
- Restore in Staging testen

---

## Projektstruktur

- `cmd/goup` – Einstiegspunkt
- `internal/app` – Bootstrapping / Verdrahtung
- `internal/config` – Env-Konfiguration
- `internal/auth` – Sessions, OIDC, Dynamic OIDC
- `internal/httpserver` – Handler, Routen, Middleware, Admin-UI
- `internal/monitor` – Checker + Runner
- `internal/notify/matrix` – Matrix-Client / Notifier
- `internal/store/sqlite` – Control- und Tenant-Store
- `web/templates` – SSR Templates
- `web/static` – CSS / statische Assets
- `docs` – Architektur-Dokumentation

---

## Security-Basics

Für produktive Deployments:

- `GOUP_AUTH_MODE=oidc` oder gezielt abgesichertes `local`
- starke zufällige Werte für `GOUP_SESSION_KEY` und `GOUP_SSO_SECRET_KEY`
- Betrieb hinter HTTPS-Reverse-Proxy
- regelmäßige Updates und Backups

---

## Roadmap (kurz)

- Public Status Page (read-only)
- feinere Rollen-/Rechteprüfung
- Export/Import und erweiterte Betriebsfunktionen
- zusätzliche Notification-Kanäle

---

## Lizenz / Beitrag

Der Quellcode ist für self-hosted Betrieb ausgelegt. Beiträge via Pull Request sind willkommen.
