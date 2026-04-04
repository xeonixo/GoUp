# GoUp

![GoUp Logo](assets/logo_goup_github.png)

**Self-hosted Uptime-Monitoring** — ein einzelner Go-Prozess, SQLite-Datenbank, nahezu keine externen Abhängigkeiten.

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![Docker](https://img.shields.io/badge/Docker-multi--arch-2496ED?logo=docker)](https://ghcr.io/xeonixo/goup)

GoUp überwacht Dienste und benachrichtigt bei Statuswechseln. Es läuft als einzelner Prozess, braucht keine Datenbank-Server und ist in wenigen Minuten betriebsbereit.

---

## Features

| Bereich | Details |
|---|---|
| **Monitor-Typen** | HTTPS, TCP, ICMP (Ping), SMTP, IMAP, DNS, UDP, WHOIS |
| **TLS** | Zertifikatsauswertung inkl. Restlaufzeit |
| **Benachrichtigungen** | E-Mail (SMTP) und Matrix bei Statuswechseln |
| **Auth** | Lokal (Username/Passwort), OIDC pro Tenant, oder deaktiviert |
| **Multi-Tenant** | Beliebig viele isolierte Tenants, je eigene DB und Auth-Provider |
| **Admin-UI** | Tenants, Provider, Benutzer, SMTP, Audit-Log |
| **Control-Plane** | Eigener Admin-Zugang mit Username/Passwort + TOTP |
| **Deployment** | Multi-Arch Docker Image (`amd64` + `arm64`) |

---

## Schnellstart

### Voraussetzungen

- Docker und Docker Compose

### 1. .env anlegen

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
### 2. Benutzer und Verzeichnis vorbereiten

Der Container-Prozess läuft als **UID 100 / GID 101** (User `goup`, Gruppe `goup`).

```bash
# Gruppe und User anlegen (IDs müssen exakt passen)
sudo groupadd --gid 101 goup
sudo useradd --uid 100 --gid 101 --no-create-home --shell /sbin/nologin --system goup

# Datenverzeichnis anlegen und Besitz setzen
sudo mkdir -p [mountpfad]
sudo chown -R 100:101 [mountpfad]
```

> Falls GID 101 auf dem Host bereits vergeben ist, reicht `sudo chown -R 100:101 [mountpfad]` —
> Docker prüft nur die numerischen IDs, nicht die Namen.

### 3. docker-compose.yml anpassen

```yaml
volumes:
  - [mountpfad]:/data
```

### 4. Starten

```bash
docker compose up -d
```

### 5. Admin-Setup abschließen

Beim ersten Start ist kein Admin-Account vorhanden. Rufe die Setup-Seite auf:

```
http://localhost:8080/admin/setup
```

Dort legst du Benutzername und Passwort für den Control-Plane-Admin an.
Optional kann direkt ein TOTP-Authenticator (z. B. Aegis, 1Password) eingerichtet werden.

### 6. Tenant anlegen

Melde dich unter `/admin/access` an, dann:

1. **Admin → Tenants → Neuer Tenant** — Slug wählen (z. B. `prod`)
2. Optional: **Providers** — OIDC oder lokale Benutzer einrichten
3. Dashboard aufrufen: `http://localhost:8080/prod/`

> **Hinweis:** Der Tenant-Slug bestimmt die URL. Ein Tenant namens `prod` ist unter `/prod/` erreichbar.
> Es gibt keinen erzwungenen `default`-Tenant — alle aktiven Tenants werden automatisch erkannt.
> Nach dem Anlegen eines neuen Tenants ist ein **Neustart des Containers** nötig, damit der Monitor-Runner
> für diesen Tenant startet.

### 7. Monitore hinzufügen

Im Dashboard über **„+ Monitor"** lassen sich Dienste anlegen. Alle Checks starten automatisch.

### Healthcheck

```
http://localhost:8080/healthz
```

---


### Image aktualisieren

```bash
docker compose pull
docker compose up -d
```

---

## Konfigurationsreferenz

Erste Einstellungen erfolgen über Umgebungsvariablen (`.env`-Datei oder direkt im Compose-File).

### Pflicht / Basis

| Variable | Standard | Beschreibung |
|---|---|---|
| `GOUP_ADDR` | `:8080` | Bind-Adresse |
| `GOUP_BASE_URL` | `http://localhost:8080` | Externe Basis-URL (wichtig für CSRF, OIDC-Callback, Links in E-Mails) |
| `GOUP_DATA_DIR` | `/data` | Datenverzeichnis für alle SQLite-Dateien |

### Sicherheit

| Variable | Beschreibung |
|---|---|
| `GOUP_SESSION_KEY` | HMAC-Schlüssel für Session-Cookies (min. 16 Zeichen). Wenn leer, wird automatisch ein Schlüssel generiert und in der DB persistiert. |
| `GOUP_SSO_SECRET_KEY` | Verschlüsselungsschlüssel für OIDC-Client-Secrets und TOTP-Secrets in der DB. Fällt auf `GOUP_SESSION_KEY` zurück wenn leer. |

> **Produktivbetrieb:** Beide Werte explizit setzen und sicher aufbewahren. Ein Verlust des Schlüssels
> macht gespeicherte OIDC-Secrets und TOTP-Konfigurationen unbrauchbar.

### Optional

| Variable | Standard | Beschreibung |
|---|---|---|
| `GOUP_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |

---

## Auth

Auth ist in GoUp **per Tenant** konfiguriert, nicht global. Ob ein Tenant eine Anmeldung möglich ist, hängt davon ab, ob für ihn Provider angelegt sind:

| Zustand | Verhalten |
|---|---|
| Tenant hat **keine** Provider | kein Zugang |
| Tenant hat **lokale Benutzer** | Login mit Username/Passwort über `/{tenantSlug}` |
| Tenant hat **OIDC-Provider** | Login über den konfigurierten OIDC-Provider |
| Tenant hat **beides** | Login-Seite zeigt beide Optionen an |

Provider werden im Admin-Bereich unter **Tenants → Provider** verwaltet. Lokale Benutzer können unter **Tenants → Benutzer** angelegt werden.

### Control-Plane Admin (getrennt von Tenant-Auth)

Der Admin-Bereich (`/admin/*`) hat einen **eigenen** Login, unabhängig von Tenant-Benutzern:

- Einrichtung beim ersten Start unter `/admin/setup`
- Login unter `/admin/access` mit Username + Passwort (+ optionalem TOTP)
- TOTP-Verwaltung unter `/admin/security`

## OCID SSO via Authentik

- Issuer URL = OpenID-Konfigurations-Aussteller
- Authentik Redirect URI = strict http(s)://domain.tld//{tenantSlug}/auth/callback
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

SMTP und IMAP unterstützen `tls` und `starttls`. Bei `https` wird das TLS-Zertifikat automatisch ausgewertet (Restlaufzeit, Ablaufdatum).

---

## Benachrichtigungen

### E-Mail

Konfiguration im Admin-Bereich unter **Settings → SMTP**. Empfänger sind automatisch alle Tenant-Benutzer
mit aktivierten E-Mail-Benachrichtigungen. Zusätzliche feste Empfänger über `GOUP_NOTIFY_EMAIL_TO`.

### Matrix

Jeder Benutzer kann in seinen Profileinstellungen (`/{tenantSlug}/settings/profile`) einen
Matrix-Homeserver, Room-ID und Access-Token hinterlegen.

---

## Betrieb hinter einem Reverse Proxy

GoUp prüft bei schreibenden Anfragen `Origin` / `Referer` gegen `GOUP_BASE_URL` (CSRF-Schutz).

**Wichtig:**
- `GOUP_BASE_URL` auf die **externe** URL setzen (inkl. Protokoll), z. B. `https://monitor.example.com`
- Der Proxy muss den `Host`-Header korrekt weiterleiten
- Für HTTPS-Betrieb werden `Secure`-Cookies und HSTS automatisch aktiviert

### Nginx-Beispiel

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

---

## ICMP / Ping

Für ICMP-Checks benötigt der Container die Capability `NET_RAW`. Diese ist in beiden Compose-Dateien bereits gesetzt.

---

## Datenhaltung & Backups

GoUp nutzt zwei SQLite-Datenbanken:

| Datei | Inhalt |
|---|---|
| `controlplane.db` | Tenants, Provider, Benutzer, Admin-Account, SMTP-Config, Audit-Log |
| `<tenant>.db` (je Tenant) | Monitore, Ergebnisse, Notification-Events |

**Backup-Empfehlung:**
- Alle `.db`-Dateien im Datenverzeichnis sichern
- Ggf. auch `-wal` und `-shm`-Dateien einschließen (bei laufendem Betrieb)
- Restore in einer Staging-Umgebung testen

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

MIT — self-hosted Betrieb erwünscht. Pull Requests willkommen.
