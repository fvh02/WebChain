# WebChain

IPFS-Pinning-Dienst. Implementiert die [IPFS Pinning Service API](https://ipfs.github.io/pinning-services-api-spec/) vor einem eigenen [Kubo](https://github.com/ipfs/kubo)-Knoten. Nur Python-Standardbibliothek (3.11+), keine Abhängigkeiten.

## Start

```bash
ipfs daemon                                  # Kubo, RPC auf 127.0.0.1:5001
python3 webchain.py add-user alice           # gibt den API-Token einmalig aus
python3 webchain.py serve                    # API auf 127.0.0.1:8080
```

Kunden nutzen den Dienst direkt mit Kubo oder IPFS Desktop:

```bash
ipfs pin remote service add webchain https://pin.example.com <TOKEN>
ipfs pin remote add --service=webchain --name=meine-seite <CID>
```

## Konfiguration (Umgebungsvariablen)

| Variable | Standard | Zweck |
|---|---|---|
| `KUBO_API` | `http://127.0.0.1:5001` | Kubo-RPC. Nie öffentlich erreichbar machen. |
| `WEBCHAIN_HOST` / `WEBCHAIN_PORT` | `127.0.0.1` / `8080` | Adresse der API |
| `WEBCHAIN_DB` | `webchain.db` | SQLite-Datei |
| `WEBCHAIN_DENYLIST` | `denylist.txt` | gesperrte CIDs, eine pro Zeile |
| `WEBCHAIN_MAX_PINS` | `1000` | Pins pro Konto |
| `WEBCHAIN_DELEGATES` | leer | Multiaddrs des Knotens, kommagetrennt |

## Login per USB-Stick

Statt den Token einzutippen, kann er als Schlüsseldatei auf einem USB-Stick liegen. Beim Anlegen einen Dateipfad auf dem Stick angeben:

```bash
python3 webchain.py add-user dave /media/usb/webchain.key
python3 webchain.py add-admin root /media/usb/admin.key
```

Auf der Login-Seite (`/account` oder `/admin`) die Datei vom Stick auswählen und „Anmelden“ klicken. Der Server speichert nur den SHA-256-Hash des Tokens. Eine vorhandene Datei wird nie überschrieben. Die Benutzer-Schlüsseldatei enthält zugleich den API-Token.

Wer die Datei kopiert, kann sich damit anmelden. Behandle den Stick wie einen Schlüssel.

## Kundenseite `/account`

Kunden melden sich mit ihrem API-Token an. Die Seite selbst läuft klassisch über diesen Server, nicht über IPFS. Sie dient nur dazu, Webseiten nach IPFS zu bringen:

- **Webseite hochladen**: Ordner als ZIP. Ein einzelner Oberordner in der ZIP wird entfernt, sodass `index.html` an der Wurzel liegt. Der Server fügt die Dateien per Kubo-RPC (`/api/v0/add`) als ein Verzeichnis ein und pinnt dessen CID.
- **Vorhandene CID pinnen** und **eigene Pins löschen**.
- Pins mit Status `pinned` haben einen Link zum Gateway (`WEBCHAIN_GATEWAY`, Standard `https://dweb.link`).

Limits: `WEBCHAIN_MAX_UPLOAD_MB` (Standard 50) für die ZIP, entpackt höchstens das Vierfache und 10 000 Dateien.

## Meldungen und Admin-Seite

- **`/report`**: öffentliches Formular für Meldungen rechtswidriger Inhalte (Art. 16 DSA). Höchstens 10 Meldungen pro IP und Stunde. Die IP wird nur im Arbeitsspeicher gezählt, nicht gespeichert.
- **`/admin`**: Suche nach CID, Pin-Name oder Kontoname. Gemeldete Treffer sind rot markiert. Darunter stehen alle offenen Meldungen mit den Knöpfen „Entfernen“ und „Ablehnen“.

Admin anlegen:

```bash
python3 webchain.py add-admin root           # gibt den Login-Token einmalig aus
```

„Entfernen“ setzt die CID auf die Sperrliste, entfernt den Pin aus Kubo, markiert alle Anfragen dafür als `failed` und schließt die Meldungen. Neue Pins der CID werden mit `403 CONTENT_BLOCKED` abgelehnt. Dasselbe geht per Kommandozeile:

```bash
python3 webchain.py block <CID>
```

Die Admin-Anmeldung setzt ein Session-Cookie mit `Secure`. Es funktioniert deshalb nur über HTTPS oder `http://localhost`.

## Betrieb

- Die API spricht nur HTTP. Davor gehört ein Reverse Proxy (Caddy, nginx) mit HTTPS und Rate Limit.
- Tokens werden nur als SHA-256-Hash gespeichert. Ein verlorener Token lässt sich nicht wiederherstellen, nur neu anlegen.
- Es werden keine Zugriffslogs geschrieben.
- Rechtliche Pflichten (Impressum, Datenschutzerklärung, AGB, AV-Vertrag, Meldeverfahren) deckt die Software nicht ab.

## Tests

```bash
python3 -m unittest -v
```

Die Tests laufen gegen einen simulierten Kubo-Knoten.
