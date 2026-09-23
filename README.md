# Benconnect Info – dynamische Website

Flask/Gunicorn-Anwendung mit Kontaktformular, SMTP-Versand über TLS (Port 465) und passwortgeschütztem Adminbereich unter `/admin`.

## Betrieb

1. `.env.example` nach `.env` kopieren und alle Zugangsdaten ersetzen. `SMTP_SERVER_IP` muss die direkte Mailserver-IP sein; `SMTP_HOST` muss zum TLS-Zertifikat passen.
2. `docker compose up -d --build` starten.
3. HTTPS-Reverse-Proxy auf `127.0.0.1:8080` konfigurieren. Dieser muss `X-Real-IP` mit der tatsächlichen Client-IP überschreiben.
4. Unter `/admin` mit `ADMIN_INITIAL_PASSWORD` anmelden und das Passwort ändern. Das Startpasswort wird nur bei der ersten Datenbankinitialisierung verwendet.

Die Inhalte und das gehashte Admin-Passwort liegen in SQLite im persistenten Docker-Volume `site-data`. Dieses Volume regelmäßig sichern und beim Aktualisieren erhalten. `.env` und Zugangsdaten niemals committen.

## Funktionen

- 33 bearbeitbare Textfelder, sofortige Veröffentlichung nach Speichern.
- Kontaktformular mit validierten Eingaben, CSRF-Schutz, Honeypot und serverseitiger Begrenzung.
- SMTP-Fehler erhalten die Formulareingaben; Erfolg wird erst nach Annahme durch den Mailserver angezeigt.
- Keine Speicherung der Kontakttexte in der Website-Datenbank.
- Sichere Session-Cookies, Passwortänderung und Abmeldung.

`python -m unittest test_app.py` führt die Tests mit temporärer Datenbank und simuliertem E-Mail-Versand aus.

Die früheren Dateien `index.html` und `style.css` im Repository-Root sind eine statische Altversion. Produktiv werden ausschließlich `app.py`, `templates/` und `static/` durch das Dockerfile verwendet. Die Datenbank überschreibt die Startwerte aus `fields.json`, sobald Texte im Adminbereich gespeichert wurden.
