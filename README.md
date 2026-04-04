# GoUp

**Self-hosted Uptime-Monitoring** — ein einzelner Go-Prozess, SQLite-Datenbank, keine externen Dienste erforderlich.

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![Docker](https://img.shields.io/badge/Docker-multi--arch-2496ED?logo=docker)](https://ghcr.io/xeonixo/goup)

GoUp überwacht Dienste und benachrichtigt bei Statuswechseln. Es läuft als einzelner Prozess, benötigt keinen Datenbank-Server und ist in wenigen Minuten einsatzbereit.

---

## Features

| Bereich | Details |
|---|---|
| **Monitor-Typen** | HTTPS, TCP, ICMP (Ping), SMTP, IMAP, DNS, UDP, WHOIS |
| **TLS** | Zertifikatsauswertung inkl. Restlaufzeit |
| **Benachrichtigungen** | E-Mail (SMTP) und Matrix bei Statuswechseln |
| **Auth** | Lokal (Username/Passwort), OIDC pro Tenant, oder öffentlich |
| **Multi-Tenant** | Beliebig viele isolierte Tenants, je eigene Datenbank und Auth-Provider |
| **Admin-UI** | Tenants, Provider, Benutzer, SMTP-Konfiguration, Audit-Log |
| **Control-Plane** | Separater Admin-Zugang mit Username/Passwort und TOTP |
| **Deployment** | Multi-Arch Docker Image (`linux/amd64` + `linux/arm64`) |

---

## Schnellstart

### Voraussetzungen

- Docker und Docker Compose
- Unter Linux: Datenverzeichnis mit korrekten Berechtigungen (siehe unten)

### 1. Konfiguration anlegen

```bash
cp .env.example .env
```

Minimale `.env` für den ersten Start:

```dotenv
GOUP_ADDR=:8080
GOUP_BASE_URL=http://localhost:8080
GOUP_DATA_DIR=/data
GOUP_LOG_LEVEL=info
```

### 2. Datenverzeichnis vorbereiten (Linux)

Der Container läuft als **UID 100 / GID 101** (`goup:goup`). Das gemountete Verzeichnis muss diesem Benutzer gehören:

```bash
sudo groupadd --gid 101 goup
sudo useradd --uid 100 --gid 101 --no-create-home --shell /sbin/nologin --system goup
sudo mkdir -p /opt/goup/data
sudo chown -R 100:101 /opt/goup/data
```

> Falls GID 101 auf dem Host bereits vergeben ist, reicht `sudo chown -R 100:101 /opt/goup/data` —
> Docker prüft nur die numerischen IDs, nicht die symbolischen Namen.

Volume in der `docker-compose.yml`:

```yaml
volumes:
  - /opt/goup/data:/data
```

### 3. Starten

```bash
docker compose up -d
```

### 4. Admin-Setup abschließen

Beim ersten Start existiert kein Admin-Account. Die Setup-Seite führt durch die Einrichtung:

```
http://localhost:8080/admin/setup
```

Benutzername und Passwort festlegen. Optional: TOTP-Authenticator (z. B. Aegis, 1Password) direkt einrichten.

### 5. Tenant anlegen

Unter `/admin/access` anmelden, dann:

1. **Tenants → Neuer Tenant** — Slug wählen (z. B. `prod`)
2. Optional: **Provider** — OIDC oder lokale Benutzer einrichten
3. Dashboard aufrufen: `http://localhost:8080/prod/`

> Der Tenant-Slug bestimmt die URL. Ein Tenant `prod` ist unter `/prod/` erreichbar.
> Nach dem Anlegen eines neuen Tenants ist ein **Neustart des Containers** nötig,
> damit der Monitor-Runner für diesen Tenant startet.

### 6. Monitore hinzufügen

Im Dashboard über **„+ Monitor"** Dienste anlegen. Checks starten automatisch.

### Healthcheck

```
GET http://localhost:8080/healthz
```

### Image aktualisieren

```bash
docker compose pull && docker compose up -d
```

---

## Konfigurationsreferenz

Alle Einstellungen erfolgen über Umgebungsvariablen (`.env`-Datei oder direkt im Compose-File).

### Pflicht / Basis

| Variable | Standard | Beschreibung |
|---|---|---|
| `GOUP_ADDR` | `:8080` | Bind-Adresse |
| `GOUP_BASE_URL` | `http://localhost:8080` | Externe Basis-URL — maßgeblich für CSRF-Prüfung, OIDC-Callbacks und Links in Benachrichtigungen |
| `GOUP_DATA_DIR` | `/data` | Verzeichnis für alle SQLite-Dateien |

### Sicherheit

| Variable | Beschreibung |
|---|---|
| `GOUP_SESSION_KEY` | HMAC-Schlüssel für Session-Cookies (min. 16 Zeichen). Wenn leer, wird automatisch ein Schlüssel generiert und in der Datenbank persistiert. |
| `GOUP_SSO_SECRET_KEY` | AES-GCM-Schlüssel zur Verschlüsselung von OIDC-Client-Secrets und TOTP-Secrets in der Datenbank. Fällt auf `GOUP_SESSION_KEY` zurück, wenn leer. |

> **Produktivbetrieb:** Beide Schlüssel explizit setzen und sicher verwahren.
> Bei Verlust sind gespeicherte OIDC-Secrets und TOTP-Konfigurationen unwiederbringlich unbrauchbar.

### Optional

| Variable | Standard | Beschreibung |
|---|---|---|
| `GOUP_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `GOUP_NOTIFY_EMAIL_TO` | — | Komma-separierte zusätzliche E-Mail-Empfänger für Benachrichtigungen |
| `GOUP_NOTIFY_EMAIL_SUBJECT_PREFIX` | — | Präfix für Benachrichtigungs-Subjects |

---

## Auth

Die Authentifizierung ist in GoUp **pro Tenant** konfiguriert — es gibt keine globale Pflicht. Ob für einen Tenant ein Login erforderlich ist, ergibt sich automatisch aus den angelegten Providern:

| Tenant-Zustand | Verhalten |
|---|---|
| Keine Provider konfiguriert | Öffentlich — kein Login erforderlich |
| Lokale Benutzer angelegt | Login mit Username/Passwort über `/{tenantSlug}/login` |
| OIDC-Provider konfiguriert | Login über den konfigurierten Identity Provider |
| Beides konfiguriert | Login-Seite zeigt beide Optionen an |

Provider und lokale Benutzer werden im Admin-Bereich unter **Tenants** verwaltet.

### Control-Plane Admin

Der Admin-Bereich (`/admin/*`) hat einen **eigenen** Login, vollständig getrennt von Tenant-Benutzern:

- Einrichtung beim ersten Start unter `/admin/setup`
- Anmeldung unter `/admin/access` mit Username + Passwort (+ optionalem TOTP)
- TOTP-Verwaltung unter `/admin/security`

### OIDC mit Authentik

| Feld | Wert |
|---|---|
| **Issuer URL** | OpenID-Konfigurations-Aussteller, z. B. `https://auth.example.com/application/o/<slug>/` |
| **Redirect URI** | `https://<goup-domain>/{tenantSlug}/auth/callback` (exakte Übereinstimmung, kein Trailing Slash) |

---

## Monitor-Typen & Zielformate

| Typ | Zielformat | Beispiel |
|---|---|---|
| `https` | URL | `https://example.com/health` |
| `http` | URL | `http://internal-service:8080/` |
| `tcp` | `host:port` | `db.internal:5432` |
| `icmp` | Hostname oder IP | `192.168.1.1` |
| `smtp` | `host:port` | `mail.example.com:587` |
| `imap` | `host:port` | `mail.example.com:993` |
| `dns` | Hostname | `example.com` |
| `udp` | `host:port` | `ntp.example.com:123` |
| `whois` | Domain | `example.com` |

SMTP und IMAP unterstützen `tls` und `starttls`. Bei `https` wird das TLS-Zertifikat automatisch ausgewertet (Gültigkeit, Ablaufdatum, Restlaufzeit).

---

## Benachrichtigungen

### E-Mail

SMTP-Konfiguration im Admin-Bereich unter **Settings → SMTP**. Benachrichtigungen gehen automatisch an alle Tenant-Benutzer mit aktivierten E-Mail-Benachrichtigungen. Zusätzliche feste Empfänger können über `GOUP_NOTIFY_EMAIL_TO` gesetzt werden.

### Matrix

Jeder Benutzer kann in seinen Profileinstellungen (`/{tenantSlug}/settings/profile`) einen Matrix-Homeserver, Room-ID und Access-Token hinterlegen.

---

## Betrieb hinter einem Reverse Proxy

GoUp validiert bei schreibenden Anfragen den `Origin`- bzw. `Referer`-Header gegen `GOUP_BASE_URL` (CSRF-Schutz). Daher gilt:

- `GOUP_BASE_URL` muss der **extern erreichbaren URL** entsprechen (inkl. Protokoll), z. B. `https://monitor.example.com`
- Der Proxy muss den `Host`-Header unverändert weiterleiten
- Bei HTTPS werden `Secure`-Cookies und HSTS automatisch aktiviert

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

---

## ICMP / Ping

ICMP-Checks benötigen die Linux-Capability `NET_RAW`. Diese ist in beiden Compose-Dateien bereits gesetzt (`cap_add: [NET_RAW]`).

Bei Bare-Metal-Deployments ohne Docker:

```bash
sudo setcap cap_net_raw=+ep /usr/local/bin/goup
```

---

## Datenhaltung & Backups

GoUp verwendet zwei getrennte SQLite-Datenbanken:

| Datei | Inhalt |
|---|---|
| `controlplane.db` | Tenants, Provider, Benutzer, Admin-Account, SMTP-Konfiguration, Audit-Log |
| `<tenantSlug>.db` (je Tenant) | Monitore, Prüfergebnisse, Benachrichtigungs-Events |

**Backup:** Alle `.db`-Dateien im Datenverzeichnis sichern. Bei laufendem Betrieb zugehörige `-wal`- und `-shm`-Dateien einschließen.

---

## Lokale Entwicklung

```bash
# Direkt starten
go run ./cmd/goup

# Mit Docker
docker compose -f docker-compose.dev.yml up -d --build

# Tests
go test ./...
```

Multi-Arch-Image selbst bauen:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/<owner>/goup:latest \
  --push .
```

---

## Projektstruktur

```
cmd/goup/               Einstiegspunkt
internal/
  app/                  Bootstrapping, Wiring
  config/               Env-Konfiguration
  auth/                 Sessions, OIDC, Dynamic OIDC, TOTP
  httpserver/           HTTP-Handler, Middleware, Admin-UI
  monitor/              Checker-Implementierungen, Runner
  notify/email/         E-Mail-Notifier
  notify/matrix/        Matrix-Client und Notifier
  store/sqlite/         Control-Plane-Store, Tenant-Store, Migrations
web/
  templates/            Server-Side Rendered HTML Templates
  static/               CSS, JavaScript
docs/
  architecture.md       Architektur-Dokumentation
```

---

## Roadmap

- [ ] Public Status Page (read-only, ohne Login)
- [ ] Webhook-Benachrichtigungen
- [ ] Feinere Rollen und Berechtigungen
- [ ] Export / Import von Monitor-Konfigurationen
- [ ] Weitere Monitor-Typen

---

## Lizenz

MIT — Self-hosted-Betrieb erwünscht. Pull Requests willkommen.
