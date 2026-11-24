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

## Takedown (Meldung nach DSA)

```bash
python3 webchain.py block <CID>
```

Setzt die CID auf die Sperrliste, entfernt den Pin aus Kubo und markiert alle Anfragen dafür als `failed`. Neue Pins der CID werden mit `403 CONTENT_BLOCKED` abgelehnt.

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
