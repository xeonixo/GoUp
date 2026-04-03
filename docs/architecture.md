# Architektur

## 1. Systemform

GoUp wird als **einzelner Hauptdienst** gebaut.

Warum:

- minimiert RAM- und CPU-Overhead
- vereinfacht Deployment, Logging und Debugging
- vermeidet verteilte Fehlerbilder für ein kleines Self-Hosted-Produkt
- erlaubt Scheduler, WebUI, OIDC und Notification-Dispatch in einem Prozess

Ein separater Worker ist für das MVP bewusst **nicht** vorgesehen.

## 2. Laufzeitaufbau

Ein Prozess enthält:

1. HTTP-Server für Admin-WebUI und spätere Public-Status-Seite
2. OIDC-Authentifizierung gegen Authentik
3. Scheduler für periodische Checks
4. Check-Runner für HTTP(S), ICMP, TCP, SMTP und IMAP
5. SQLite-Store
6. Notification-Dispatcher für Matrix

## 3. Architekturprinzipien

- SSR statt schwerem SPA
- Standardbibliothek bevorzugen
- keine CQRS-/Event-Sourcing-Komplexität
- SQLite als Standard, später abstrahierbar
- kleine, klar getrennte Pakete statt Microservices
- Background Jobs im selben Dienst
- stabile Interfaces nur dort, wo echte Austauschbarkeit erwartet ist

## 4. Sicherheitsmodell

### OIDC mit Authentik

Empfohlener Flow:

- Authorization Code Flow
- serverseitiger Callback
- Verifikation von ID Token und Nonce
- signierte Session-Cookies
- kurze Session-Laufzeit, erneute OIDC-Anmeldung bei Ablauf

Warum kein lokaler Passwort-Login im MVP:

- reduziert Angriffsfläche
- vermeidet Passwortspeicherung
- passt zum SSO-Ziel

### Cookies/Sessions

- `HttpOnly`
- `Secure` sobald hinter HTTPS betrieben
- `SameSite=Lax`
- HMAC-signiert
- optional später verschlüsselt

## 5. Monitoring-Modell

### Monitor-Typen im MVP

- `https`
- `tcp`
- `icmp`
- `smtp`
- `imap`

### Check-Ergebnis pro Lauf

Ein Check speichert:

- Zielstatus (`up`/`down`/`degraded`)
- Latenz in Millisekunden
- Fehlermeldung
- HTTP-Statuscode falls relevant
- TLS-Metadaten falls relevant
- Ablaufdatum des Zertifikats
- Restlaufzeit des Zertifikats in Sekunden

### STARTTLS/TLS

Für SMTP/IMAP wird zwischen diesen Modi unterschieden:

- direktes TLS
- Plain + STARTTLS
- optional Plain ohne TLS nur für Diagnosezwecke

Das Datenmodell speichert daher Transport- und TLS-Modus explizit.

## 6. Datenmodell

### Tabelle `users`

- `id`
- `oidc_subject` eindeutig
- `email`
- `display_name`
- `role`
- `created_at`
- `updated_at`
- `last_login_at`

### Tabelle `monitors`

- `id`
- `name`
- `kind` (`https`, `tcp`, `icmp`, `smtp`, `imap`)
- `target`
- `interval_seconds`
- `timeout_seconds`
- `enabled`
- `tls_mode` (`none`, `tls`, `starttls`)
- `expected_status_code` nullable
- `expected_text` nullable
- `notify_on_recovery`
- `created_at`
- `updated_at`

Hinweis: Zieltyp-spezifische Details können anfangs als JSON-Blob gespeichert werden, solange das Schema klein bleibt. Für das MVP ist das akzeptabel und ressourcenschonend.

### Tabelle `monitor_results`

- `id`
- `monitor_id`
- `checked_at`
- `status`
- `latency_ms`
- `message`
- `http_status_code` nullable
- `tls_valid` nullable
- `tls_not_after` nullable
- `tls_days_remaining` nullable

### Tabelle `incidents`

- `id`
- `monitor_id`
- `started_at`
- `resolved_at` nullable
- `cause`
- `last_state`

### Tabelle `notification_endpoints`

- `id`
- `kind` (`matrix`)
- `name`
- `enabled`
- `config_json`
- `created_at`
- `updated_at`

### Tabelle `notification_events`

- `id`
- `monitor_id`
- `endpoint_id`
- `event_type`
- `created_at`
- `delivered_at` nullable
- `error_message` nullable

### Tabelle `app_settings`

- `key`
- `value`
- `updated_at`

Hier landen später WebUI-basierte Einstellungen wie Branding, Default-Intervalle oder Public-Status-Optionen.

## 7. SQLite-Strategie

- WAL-Modus aktivieren
- `busy_timeout` setzen
- ein gemeinsamer DB-Handle im Prozess
- einfache Migrationen beim Start
- Backups über Dateikopie nach Checkpoint oder SQLite-Backup-Mechanismus

SQLite ist für das Zielprofil ideal:

- kein externer Datenbankdienst nötig
- minimaler RAM-Footprint
- robuste Persistenz für kleine bis mittlere Installationen

## 8. UI-/API-Konzept

### Admin-WebUI

- Dashboard mit Monitorübersicht
- Formulare für Monitore, Notification-Ziele und Systemeinstellungen
- Login/Logout via OIDC
- Tabellenansichten statt JS-lastigem Client-State

### Öffentliche Statusseite

Architektonisch von Anfang an mitgedacht:

- eigenes Handler-Modul
- nur lesender Zugriff
- separater Scope im Routing
- Datenbasis aus denselben Monitor- und Ergebnis-Tabellen

### JSON-API

Nicht Fokus des MVP. Falls benötigt:

- interne JSON-Endpunkte für kleine Progressive-Enhancement-Funktionen
- später stabile API-Versionierung, falls Automatisierung relevant wird

## 9. Libraries im MVP

- Go-Standardbibliothek für HTTP, TLS, SMTP-nahe Verbindungen, Templates, JSON, Logging
- `modernc.org/sqlite` für SQLite ohne CGO
- `github.com/coreos/go-oidc/v3/oidc` für OIDC
- `golang.org/x/oauth2` für OAuth2/OIDC Login

Bewusst nicht im MVP:

- großes Frontend-Framework
- schweres ORM
- vollständiges Matrix-SDK
- Message-Broker

## 10. Phasen

### Phase 1: MVP

Features:

- Grunddienst, Docker, SQLite, SSR-WebUI
- OIDC-Login
- Monitorverwaltung
- HTTPS/TCP/ICMP/SMTP/IMAP-Checks
- Matrix-Benachrichtigung
- Healthcheck, Logging, Backup-Grundlagen

Risiken:

- ICMP im Containerbetrieb
- STARTTLS-Randfälle
- saubere Statuswechsel-Logik ohne Alarmflattern

### Phase 2: Produktionsreife Kernfunktionen

Features:

- Incident-Lifecycle
- Retry-/Quorum-Logik
- Wartungsfenster
- Rollenmodell
- Export/Import
- Public Status Page
- History-Aggregation

Risiken:

- Reporting ohne überkomplexe Historisierung
- Berechtigungsmodell schlank halten

### Phase 3: Komfortfunktionen

Features:

- Filter/Tags/Gruppen
- mehrere Benachrichtigungskanäle
- kleine API
- bessere Auswertungen
- UX-Verbesserungen

Risiken:

- Scope-Drift
- unnötiger Ressourcenanstieg
