#!/usr/bin/env python3
"""WebChain: IPFS pinning service implementing the IPFS Pinning Service API
(https://ipfs.github.io/pinning-services-api-spec/) in front of a Kubo node.

Usage:
  python3 webchain.py serve              start the API server
  python3 webchain.py add-user <name>    create a user, print its API token
  python3 webchain.py add-admin <name>   create an admin, print its login token
  python3 webchain.py block <cid>        takedown: deny-list, unpin, fail all requests

Web pages: /account (users: upload a website ZIP, manage pins), /admin (search pins, handle
reports, remove content), /report (public notice form). They are served by this server, not via IPFS.
"""
import contextlib
import datetime
import email.parser
import email.policy
import hashlib
import html
import io
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = os.environ.get("WEBCHAIN_DB", "webchain.db")
KUBO = os.environ.get("KUBO_API", "http://127.0.0.1:5001").rstrip("/")
DENYLIST = os.environ.get("WEBCHAIN_DENYLIST", "denylist.txt")
HOST = os.environ.get("WEBCHAIN_HOST", "127.0.0.1")
PORT = int(os.environ.get("WEBCHAIN_PORT", "8080"))
MAX_PINS = int(os.environ.get("WEBCHAIN_MAX_PINS", "1000"))
DELEGATES = [d for d in os.environ.get("WEBCHAIN_DELEGATES", "").split(",") if d]
MAX_BODY = 64 * 1024
SESSION_TTL = 8 * 3600
MAX_UPLOAD = int(os.environ.get("WEBCHAIN_MAX_UPLOAD_MB", "50")) * 1024 * 1024
MAX_UNZIPPED = 4 * MAX_UPLOAD
MAX_FILES = 10000
GATEWAY = os.environ.get("WEBCHAIN_GATEWAY", "https://dweb.link").rstrip("/")

# CIDv0 (base58 "Qm...") or CIDv1 in base32 ("b...") - the forms Kubo prints.
CID_RE = re.compile(r"^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{20,200})$")
STATUSES = {"queued", "pinning", "pinned", "failed"}
_deny_lock = threading.Lock()


@contextlib.contextmanager
def db():
    """Connection that commits on success, rolls back on error, and always closes."""
    con = sqlite3.connect(DB, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    try:
        with con:
            yield con
    finally:
        con.close()


def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS pins (
          requestid TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          cid TEXT NOT NULL, name TEXT, origins TEXT NOT NULL, meta TEXT NOT NULL,
          status TEXT NOT NULL, created REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS pins_user ON pins(user_id, created);
        CREATE INDEX IF NOT EXISTS pins_cid ON pins(cid);
        CREATE TABLE IF NOT EXISTS admins (
          token_hash TEXT PRIMARY KEY, name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (
          id_hash TEXT PRIMARY KEY, admin TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS reports (
          id INTEGER PRIMARY KEY, cid TEXT NOT NULL, reason TEXT NOT NULL, contact TEXT,
          status TEXT NOT NULL DEFAULT 'open', created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS user_sessions (
          id_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS reports_cid ON reports(cid, status);
        """)


def token_hash(token):
    # Tokens are 256-bit random, so a fast hash is enough (no password stretching needed).
    return hashlib.sha256(token.encode()).hexdigest()


def denied(cid):
    # shortcut: plain-CID list only; for the hashed "badbits" format add a double-hash check.
    try:
        with open(DENYLIST) as f:
            return cid in {line.strip() for line in f}
    except FileNotFoundError:
        return False


def kubo(cmd, cid):
    url = f"{KUBO}/api/v0/{cmd}?arg={urllib.parse.quote(cid)}"
    with urllib.request.urlopen(urllib.request.Request(url, method="POST"), timeout=3600) as r:
        r.read()


def set_status(requestid, status):
    with db() as con:
        return con.execute("UPDATE pins SET status=? WHERE requestid=? AND status!='failed'",
                           (status, requestid)).rowcount


def pin_worker(requestid, cid):
    set_status(requestid, "pinning")
    try:
        kubo("pin/add", cid)
    except Exception:
        set_status(requestid, "failed")
        return
    if not set_status(requestid, "pinned"):
        unpin_if_unused(cid)  # deleted or blocked while pinning


def start_pin(requestid, cid):
    threading.Thread(target=pin_worker, args=(requestid, cid), daemon=True).start()


def unpin_if_unused(cid):
    with db() as con:
        used = con.execute("SELECT 1 FROM pins WHERE cid=? AND status!='failed'", (cid,)).fetchone()
    if not used:
        try:
            kubo("pin/rm", cid)
        except Exception:
            pass  # not pinned (yet) or already removed


def delete_pin(con, user_id, requestid):
    """Delete a user's own pin request; True if it existed. Unpins once no one else needs the CID."""
    row = con.execute("SELECT cid FROM pins WHERE requestid=? AND user_id=?",
                      (requestid, user_id)).fetchone()
    if not row:
        return False
    con.execute("DELETE FROM pins WHERE requestid=?", (requestid,))
    con.commit()
    unpin_if_unused(row["cid"])
    return True


def zip_to_kubo(data):
    """Add a website ZIP to Kubo as one directory; return the root CID (not pinned yet)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        files = [i for i in zf.infolist() if not i.is_dir()]
    except zipfile.BadZipFile:
        raise ApiError(400, "BAD_REQUEST", "Keine gültige ZIP-Datei.")
    if not files:
        raise ApiError(400, "BAD_REQUEST", "Die ZIP-Datei ist leer.")
    if len(files) > MAX_FILES or sum(i.file_size for i in files) > MAX_UNZIPPED:
        raise ApiError(413, "BAD_REQUEST", "Die ZIP-Datei ist entpackt zu groß.")
    names = [i.filename for i in files]
    for n in names:
        if n.startswith("/") or "\\" in n or any(seg in ("", ".", "..") for seg in n.split("/")):
            raise ApiError(400, "BAD_REQUEST", "Ungültiger Dateipfad in der ZIP-Datei.")
    # A zipped folder "meine-seite/..." should serve its contents at the root.
    tops = {n.split("/")[0] for n in names}
    strip = len(tops) == 1 and all("/" in n for n in names)
    boundary = secrets.token_hex(16)
    parts, dirs = [], set()

    def part(path, ctype, content=b""):
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                     f'filename="{urllib.parse.quote_plus(path, safe="")}"\r\n'
                     f"Content-Type: {ctype}\r\n\r\n".encode() + content + b"\r\n")

    part("site", "application/x-directory")
    for info in sorted(files, key=lambda i: i.filename):
        rel = info.filename.split("/", 1)[1] if strip else info.filename
        segs = rel.split("/")
        for k in range(1, len(segs)):  # parent directories must come before their files
            d = "/".join(segs[:k])
            if d not in dirs:
                dirs.add(d)
                part("site/" + d, "application/x-directory")
        part("site/" + rel, "application/octet-stream", zf.read(info))
    # shortcut: whole request is built in memory (bounded by MAX_UNZIPPED); stream it if limits grow.
    body = b"".join(parts) + f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{KUBO}/api/v0/add?cid-version=1&pin=false&quieter=true",
                                 data=body, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=600) as r:
        lines = [ln for ln in r.read().decode().splitlines() if ln.strip()]
    return json.loads(lines[-1])["Hash"]


def iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.UTC).isoformat().replace("+00:00", "Z")


def parse_ts(s):
    return datetime.datetime.fromisoformat(s).timestamp()


def pin_status(row):
    return {
        "requestid": row["requestid"],
        "status": row["status"],
        "created": iso(row["created"]),
        "pin": {"cid": row["cid"], "name": row["name"],
                "origins": json.loads(row["origins"]), "meta": json.loads(row["meta"])},
        "delegates": DELEGATES,
        "info": {},
    }


class ApiError(Exception):
    def __init__(self, code, reason, details=""):
        super().__init__(reason)
        self.code, self.reason, self.details = code, reason, details


def validate_pin(body):
    if not isinstance(body, dict):
        raise ApiError(400, "BAD_REQUEST", "body must be a JSON object")
    cid, name = body.get("cid"), body.get("name")
    origins, meta = body.get("origins", []), body.get("meta", {})
    if not isinstance(cid, str) or not CID_RE.match(cid):
        raise ApiError(400, "BAD_REQUEST", "invalid cid")
    if name is not None and (not isinstance(name, str) or len(name) > 255):
        raise ApiError(400, "BAD_REQUEST", "name must be a string of max 255 chars")
    if (not isinstance(origins, list) or len(origins) > 20
            or not all(isinstance(o, str) and len(o) <= 512 for o in origins)):
        raise ApiError(400, "BAD_REQUEST", "origins must be a list of multiaddr strings")
    if (not isinstance(meta, dict) or len(meta) > 50
            or not all(isinstance(k, str) and isinstance(v, str) and len(k) + len(v) <= 1024
                       for k, v in meta.items())):
        raise ApiError(400, "BAD_REQUEST", "meta must be a map of strings")
    if denied(cid):
        raise ApiError(403, "CONTENT_BLOCKED", "this CID is blocked")
    return cid, name, origins, meta


def create_pin(con, user_id, body):
    cid, name, origins, meta = validate_pin(body)
    count = con.execute("SELECT COUNT(*) FROM pins WHERE user_id=? AND status!='failed'",
                        (user_id,)).fetchone()[0]
    if count >= MAX_PINS:
        raise ApiError(429, "QUOTA_EXCEEDED", f"max {MAX_PINS} pins per account")
    requestid = str(uuid.uuid4())
    con.execute("INSERT INTO pins VALUES (?,?,?,?,?,?,?,?)",
                (requestid, user_id, cid, name, json.dumps(origins), json.dumps(meta),
                 "queued", datetime.datetime.now(datetime.UTC).timestamp()))
    return requestid, cid


class Handler(BaseHTTPRequestHandler):
    server_version = "WebChain"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass  # no access logs: avoids storing IPs/tokens (DSGVO data minimisation)

    def send_json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def user_id(self, con):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise ApiError(401, "UNAUTHORIZED", "missing bearer token")
        row = con.execute("SELECT id FROM users WHERE token_hash=?",
                          (token_hash(auth[7:].strip()),)).fetchone()
        if not row:
            raise ApiError(401, "UNAUTHORIZED", "invalid token")
        return row["id"]

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ApiError(413, "BAD_REQUEST", "body too large")
        try:
            return json.loads(self.rfile.read(length) or b"null")
        except ValueError:
            raise ApiError(400, "BAD_REQUEST", "invalid JSON")

    def own_pin(self, con, uid, requestid):
        row = con.execute("SELECT * FROM pins WHERE requestid=? AND user_id=?",
                          (requestid, uid)).fetchone()
        if not row:
            raise ApiError(404, "NOT_FOUND", "pin request not found")
        return row

    def handle_api(self, method):
        url = urllib.parse.urlsplit(self.path)
        parts = [p for p in url.path.split("/") if p]
        if not parts or parts[0] != "pins" or len(parts) > 2:
            raise ApiError(404, "NOT_FOUND", "unknown path")
        with db() as con:
            uid = self.user_id(con)
            if len(parts) == 1 and method == "GET":
                return self.send_json(200, self.list_pins(con, uid, url.query))
            if len(parts) == 1 and method == "POST":
                requestid, cid = create_pin(con, uid, self.body())
                con.commit()
                start_pin(requestid, cid)
                return self.send_json(202, pin_status(self.own_pin(con, uid, requestid)))
            if len(parts) == 2 and method == "GET":
                return self.send_json(200, pin_status(self.own_pin(con, uid, parts[1])))
            if len(parts) == 2 and method == "POST":  # replace
                old = self.own_pin(con, uid, parts[1])
                body = self.body()
                con.execute("DELETE FROM pins WHERE requestid=?", (old["requestid"],))
                requestid, cid = create_pin(con, uid, body)
                con.commit()
                start_pin(requestid, cid)
                if old["cid"] != cid:
                    unpin_if_unused(old["cid"])
                return self.send_json(202, pin_status(self.own_pin(con, uid, requestid)))
            if len(parts) == 2 and method == "DELETE":
                if not delete_pin(con, uid, parts[1]):
                    raise ApiError(404, "NOT_FOUND", "pin request not found")
                self.send_response(202)
                self.send_header("Content-Length", "0")
                return self.end_headers()
        raise ApiError(405, "BAD_REQUEST", "method not allowed")

    def list_pins(self, con, uid, query):
        # shortcut: name filter is exact match only and meta filter is ignored; add if clients need them.
        q = dict(urllib.parse.parse_qsl(query))
        where, args = ["user_id=?"], [uid]
        statuses = q.get("status", "pinned").split(",")
        if not set(statuses) <= STATUSES:
            raise ApiError(400, "BAD_REQUEST", "invalid status")
        where.append(f"status IN ({','.join('?' * len(statuses))})")
        args += statuses
        if "cid" in q:
            cids = q["cid"].split(",")[:10]
            where.append(f"cid IN ({','.join('?' * len(cids))})")
            args += cids
        if "name" in q:
            where.append("name=?")
            args.append(q["name"])
        try:
            if "before" in q:
                where.append("created<?")
                args.append(parse_ts(q["before"]))
            if "after" in q:
                where.append("created>?")
                args.append(parse_ts(q["after"]))
            limit = min(max(int(q.get("limit", 10)), 1), 1000)
        except ValueError:
            raise ApiError(400, "BAD_REQUEST", "invalid before/after/limit")
        sql_where = " AND ".join(where)
        count = con.execute(f"SELECT COUNT(*) FROM pins WHERE {sql_where}", args).fetchone()[0]
        rows = con.execute(f"SELECT * FROM pins WHERE {sql_where} ORDER BY created DESC LIMIT ?",
                           args + [limit]).fetchall()
        return {"count": count, "results": [pin_status(r) for r in rows]}

    # ---- admin + report web pages (server-rendered, no JS) ----

    def send_html(self, code, title, body, headers=()):
        data = PAGE.format(title=html.escape(title), body=body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")  # no-referrer makes browsers send "Origin: null"
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                         "frame-ancestors 'none'; base-uri 'none'")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, headers=()):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()

    def form(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ApiError(413, "BAD_REQUEST", "body too large")
        return dict(urllib.parse.parse_qsl(self.rfile.read(length).decode("utf-8", "replace")))

    def same_origin(self):
        # CSRF defence on top of SameSite=Strict: browsers send Origin on form POSTs.
        origin = self.headers.get("Origin")
        return origin is None or urllib.parse.urlsplit(origin).netloc == self.headers.get("Host")

    def session_admin(self, con):
        cookie = self.headers.get("Cookie", "")
        sid = next((c.split("=", 1)[1] for c in cookie.split("; ") if c.startswith("wc_session=")), "")
        if not sid:
            return None
        con.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
        row = con.execute("SELECT admin FROM sessions WHERE id_hash=?", (token_hash(sid),)).fetchone()
        return row["admin"] if row else None

    def handle_web(self, method, path, query):
        if method == "POST" and not self.same_origin():
            return self.send_html(403, "Fehler", "<p>Ungültige Herkunft.</p>")
        if path == "/report":
            return self.report_page(method)
        with db() as con:
            if path == "/admin/login" and method == "POST":
                f = self.form()
                row = con.execute("SELECT name FROM admins WHERE token_hash=?",
                                  (token_hash(f.get("token", "").strip()),)).fetchone()
                if not row:
                    return self.send_html(401, "Anmeldung", LOGIN_FORM.format(msg="Falscher Token."))
                sid = secrets.token_urlsafe(32)
                con.execute("INSERT INTO sessions VALUES (?,?,?)",
                            (token_hash(sid), row["name"], time.time() + SESSION_TTL))
                return self.redirect("/admin", [("Set-Cookie",
                    f"wc_session={sid}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL}")])
            admin = self.session_admin(con)
            if not admin:
                if method == "POST":
                    return self.redirect("/admin")
                return self.send_html(200, "Anmeldung", LOGIN_FORM.format(msg=""))
            if path == "/admin" and method == "GET":
                return self.send_html(200, "Admin", admin_page(con, admin, query))
            if method == "POST":
                f = self.form()
                if path == "/admin/logout":
                    con.execute("DELETE FROM sessions WHERE admin=?", (admin,))
                    return self.redirect("/admin", [("Set-Cookie",
                        "wc_session=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0")])
                if path == "/admin/remove" and CID_RE.match(f.get("cid", "")):
                    con.commit()
                    block(f["cid"])
                    return self.redirect("/admin?" + urllib.parse.urlencode({"q": f["cid"]}))
                if path == "/admin/reject" and f.get("id", "").isdigit():
                    con.execute("UPDATE reports SET status='rejected' WHERE id=? AND status='open'",
                                (int(f["id"]),))
                    return self.redirect("/admin")
        self.send_html(404, "Nicht gefunden", "<p>Seite nicht gefunden.</p>")

    def session_user(self, con):
        cookie = self.headers.get("Cookie", "")
        sid = next((c.split("=", 1)[1] for c in cookie.split("; ") if c.startswith("wc_user=")), "")
        if not sid:
            return None
        con.execute("DELETE FROM user_sessions WHERE expires<?", (time.time(),))
        row = con.execute("SELECT user_id FROM user_sessions WHERE id_hash=?", (token_hash(sid),)).fetchone()
        return row["user_id"] if row else None

    def upload_fields(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD:
            raise ApiError(413, "BAD_REQUEST", f"Datei zu groß (max. {MAX_UPLOAD // 2**20} MB).")
        head = f"Content-Type: {self.headers.get('Content-Type', '')}\r\n\r\n".encode()
        msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(head + self.rfile.read(length))
        if not msg.is_multipart():
            raise ApiError(400, "BAD_REQUEST", "Ungültiger Upload.")
        return {p.get_param("name", header="content-disposition"): p.get_payload(decode=True)
                for p in msg.iter_parts()}

    def handle_account(self, method, path, query):
        if method == "POST" and not self.same_origin():
            return self.send_html(403, "Fehler", "<p>Ungültige Herkunft.</p>")
        cookie_attrs = "Path=/account; HttpOnly; Secure; SameSite=Strict"
        with db() as con:
            if path == "/account/login" and method == "POST":
                row = con.execute("SELECT id FROM users WHERE token_hash=?",
                                  (token_hash(self.form().get("token", "").strip()),)).fetchone()
                if not row:
                    return self.send_html(401, "Anmeldung", USER_LOGIN_FORM.format(msg="Falscher Token."))
                sid = secrets.token_urlsafe(32)
                con.execute("INSERT INTO user_sessions VALUES (?,?,?)",
                            (token_hash(sid), row["id"], time.time() + SESSION_TTL))
                return self.redirect("/account", [("Set-Cookie",
                    f"wc_user={sid}; {cookie_attrs}; Max-Age={SESSION_TTL}")])
            uid = self.session_user(con)
            if not uid:
                if method == "POST":
                    return self.redirect("/account")
                return self.send_html(200, "Anmeldung", USER_LOGIN_FORM.format(msg=""))
            if path == "/account" and method == "GET":
                return self.send_html(200, "Meine Webseiten", account_page(con, uid, query))
            if method != "POST":
                return self.send_html(404, "Nicht gefunden", "<p>Seite nicht gefunden.</p>")
            try:
                if path == "/account/upload":
                    f = self.upload_fields()
                    name = (f.get("name") or b"").decode("utf-8", "replace").strip() or None
                    if not f.get("site"):
                        raise ApiError(400, "BAD_REQUEST", "Bitte eine ZIP-Datei auswählen.")
                    cid = zip_to_kubo(f["site"])
                    requestid, cid = create_pin(con, uid, {"cid": cid, "name": name})
                    con.commit()
                    start_pin(requestid, cid)
                    return self.redirect("/account?" + urllib.parse.urlencode(
                        {"msg": f"Hochgeladen. CID: {cid}"}))
                f = self.form()
                if path == "/account/logout":
                    con.execute("DELETE FROM user_sessions WHERE user_id=?", (uid,))
                    return self.redirect("/account", [("Set-Cookie", f"wc_user=; {cookie_attrs}; Max-Age=0")])
                if path == "/account/pin":
                    requestid, cid = create_pin(con, uid, {"cid": f.get("cid", "").strip(),
                                                           "name": f.get("name", "").strip() or None})
                    con.commit()
                    start_pin(requestid, cid)
                    return self.redirect("/account?msg=Pin+angelegt.")
                if path == "/account/delete":
                    delete_pin(con, uid, f.get("requestid", ""))
                    return self.redirect("/account?msg=Gel%C3%B6scht.")
            except ApiError as e:
                return self.redirect("/account?" + urllib.parse.urlencode({"msg": e.details}))
            except (OSError, ValueError, KeyError):
                return self.redirect("/account?msg=IPFS-Knoten+nicht+erreichbar.")
        self.send_html(404, "Nicht gefunden", "<p>Seite nicht gefunden.</p>")

    def report_page(self, method):
        if method == "GET":
            return self.send_html(200, "Inhalt melden", REPORT_FORM.format(msg=""))
        if method != "POST":
            return self.send_html(405, "Fehler", "<p>Nicht erlaubt.</p>")
        if not report_rate_ok(self.client_address[0]):
            return self.send_html(429, "Inhalt melden",
                                  REPORT_FORM.format(msg="Zu viele Meldungen. Bitte später erneut."))
        f = self.form()
        cid, reason, contact = (f.get("cid", "").strip(), f.get("reason", "").strip(),
                                f.get("contact", "").strip())
        if not CID_RE.match(cid) or not 10 <= len(reason) <= 5000 or len(contact) > 255:
            return self.send_html(400, "Inhalt melden", REPORT_FORM.format(
                msg="Bitte gültige CID und eine Begründung (mind. 10 Zeichen) angeben."))
        with db() as con:
            con.execute("INSERT INTO reports (cid, reason, contact, created) VALUES (?,?,?,?)",
                        (cid, reason, contact or None, time.time()))
        self.send_html(200, "Danke", "<p>Danke. Ihre Meldung wurde gespeichert und wird geprüft.</p>")

    def dispatch(self, method):
        try:
            url = urllib.parse.urlsplit(self.path)
            if url.path == "/account" or url.path.startswith("/account/"):
                return self.handle_account(method, url.path, url.query)
            if url.path == "/report" or url.path == "/admin" or url.path.startswith("/admin/"):
                return self.handle_web(method, url.path, url.query)
            self.handle_api(method)
        except ApiError as e:
            self.send_json(e.code, {"error": {"reason": e.reason, "details": e.details}})
        except Exception:
            self.send_json(500, {"error": {"reason": "INTERNAL_SERVER_ERROR", "details": ""}})

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_DELETE(self):
        self.dispatch("DELETE")


def resume_pending():
    with db() as con:
        rows = con.execute("SELECT requestid, cid FROM pins WHERE status IN ('queued','pinning')").fetchall()
    for r in rows:
        start_pin(r["requestid"], r["cid"])


def serve():
    init_db()
    resume_pending()
    print(f"WebChain listening on http://{HOST}:{PORT} (Kubo: {KUBO})")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


def add_user(name):
    init_db()
    token = secrets.token_urlsafe(32)
    with db() as con:
        con.execute("INSERT INTO users (name, token_hash) VALUES (?,?)", (name, token_hash(token)))
    print(token)


def block(cid):
    """Takedown: deny-list the CID, fail its pin requests, close its reports, unpin it."""
    init_db()
    with _deny_lock, open(DENYLIST, "a") as f:
        f.write(cid + "\n")
    with db() as con:
        n = con.execute("UPDATE pins SET status='failed' WHERE cid=?", (cid,)).rowcount
        con.execute("UPDATE reports SET status='removed' WHERE cid=? AND status='open'", (cid,))
    try:
        kubo("pin/rm", cid)
    except Exception:
        pass
    return n


def add_admin(name):
    init_db()
    token = secrets.token_urlsafe(32)
    with db() as con:
        con.execute("INSERT INTO admins VALUES (?,?)", (token_hash(token), name))
    print(token)


_report_hits = {}
_report_lock = threading.Lock()


def report_rate_ok(ip, limit=10, window=3600):
    """Max `limit` reports per IP per window. Kept in memory only, never stored."""
    now = time.time()
    with _report_lock:
        hits = [t for t in _report_hits.get(ip, []) if t > now - window]
        if len(hits) >= limit:
            return False
        _report_hits[ip] = hits + [now]
        return True


def admin_page(con, admin, query):
    e = html.escape
    q = dict(urllib.parse.parse_qsl(query)).get("q", "").strip()[:255]
    out = [f'<p>Angemeldet als <b>{e(admin)}</b></p>'
           '<form method="post" action="/admin/logout"><button>Abmelden</button></form>'
           f'<h2>Suche</h2><form method="get" action="/admin">'
           f'<label>CID, Name oder Konto <input name="q" value="{e(q)}" size="60"></label> '
           '<button>Suchen</button></form>']

    def remove_btn(cid):
        return ('<form method="post" action="/admin/remove">'
                f'<input type="hidden" name="cid" value="{e(cid)}">'
                '<button>Entfernen</button></form>')

    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = con.execute(
            "SELECT p.cid, p.name, p.status, p.created, u.name AS account,"
            " (SELECT COUNT(*) FROM reports r WHERE r.cid=p.cid AND r.status='open') AS reports"
            " FROM pins p JOIN users u ON u.id=p.user_id"
            " WHERE p.cid=? OR p.name LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\'"
            " ORDER BY reports DESC, p.created DESC LIMIT 100", (q, like, like)).fetchall()
        out.append(f"<h3>{len(rows)} Treffer</h3>")
        if rows:
            out.append("<table><tr><th>CID</th><th>Name</th><th>Konto</th><th>Status</th>"
                       "<th>Erstellt</th><th>Offene Meldungen</th><th></th></tr>")
            for r in rows:
                out.append(f'<tr{" class=rep" if r["reports"] else ""}><td><code>{e(r["cid"])}</code></td>'
                           f'<td>{e(r["name"] or "")}</td><td>{e(r["account"])}</td><td>{e(r["status"])}</td>'
                           f'<td>{iso(r["created"])[:16]}</td><td>{r["reports"]}</td>'
                           f'<td>{remove_btn(r["cid"]) if r["status"] != "failed" else ""}</td></tr>')
            out.append("</table>")

    reports = con.execute("SELECT * FROM reports WHERE status='open' ORDER BY created LIMIT 200").fetchall()
    out.append(f"<h2>Offene Meldungen ({len(reports)})</h2>")
    if reports:
        out.append("<table><tr><th>Eingang</th><th>CID</th><th>Begründung</th><th>Kontakt</th><th></th></tr>")
        for r in reports:
            link = "/admin?" + urllib.parse.urlencode({"q": r["cid"]})
            out.append(f'<tr><td>{iso(r["created"])[:16]}</td>'
                       f'<td><a href="{e(link)}"><code>{e(r["cid"])}</code></a></td>'
                       f'<td>{e(r["reason"])}</td><td>{e(r["contact"] or "")}</td><td>{remove_btn(r["cid"])}'
                       '<form method="post" action="/admin/reject">'
                       f'<input type="hidden" name="id" value="{r["id"]}"><button>Ablehnen</button></form></td></tr>')
        out.append("</table>")
    return "".join(out)


def account_page(con, uid, query):
    e = html.escape
    msg = dict(urllib.parse.parse_qsl(query)).get("msg", "")[:300]
    name = con.execute("SELECT name FROM users WHERE id=?", (uid,)).fetchone()["name"]
    out = [f'<p role="status">{e(msg)}</p>' if msg else "",
           f'<p>Angemeldet als <b>{e(name)}</b></p>'
           '<form method="post" action="/account/logout"><button>Abmelden</button></form>'
           '<h2>Webseite hochladen</h2>'
           '<p>Packe den Ordner deiner Webseite als ZIP. Er muss eine <code>index.html</code> enthalten '
           'und relative Pfade nutzen (<code>./style.css</code>, nicht <code>/style.css</code>).</p>'
           '<form method="post" action="/account/upload" enctype="multipart/form-data">'
           '<p><label>ZIP-Datei<br><input type="file" name="site" accept=".zip,application/zip" required></label></p>'
           '<p><label>Name (optional)<br><input name="name" maxlength="255"></label></p>'
           f'<p><button>Hochladen</button> (max. {MAX_UPLOAD // 2**20} MB)</p></form>'
           '<h2>Vorhandene CID pinnen</h2><form method="post" action="/account/pin">'
           '<label>CID <input name="cid" required size="60"></label> '
           '<label>Name <input name="name" maxlength="255"></label> <button>Pinnen</button></form>']
    rows = con.execute("SELECT * FROM pins WHERE user_id=? ORDER BY created DESC LIMIT 200", (uid,)).fetchall()
    out.append(f"<h2>Meine Pins ({len(rows)})</h2>")
    if rows:
        out.append("<table><tr><th>Name</th><th>CID</th><th>Status</th><th>Erstellt</th><th></th></tr>")
        for r in rows:
            link = (f'<a href="{e(GATEWAY)}/ipfs/{e(r["cid"])}/" target="_blank" rel="noopener noreferrer">Öffnen</a>'
                    if r["status"] == "pinned" else "")
            out.append(f'<tr><td>{e(r["name"] or "")}</td><td><code>{e(r["cid"])}</code></td>'
                       f'<td>{e(r["status"])}</td><td>{iso(r["created"])[:16]}</td><td>{link} '
                       '<form method="post" action="/account/delete">'
                       f'<input type="hidden" name="requestid" value="{e(r["requestid"])}">'
                       '<button>Löschen</button></form></td></tr>')
        out.append("</table><p>Status <code>queued</code>/<code>pinning</code>? Seite neu laden.</p>")
    return "".join(out)


USER_LOGIN_FORM = """<p>{msg}</p><form method="post" action="/account/login">
<label>API-Token <input type="password" name="token" required autocomplete="current-password"></label>
<button>Anmelden</button></form>"""

PAGE = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title} - WebChain</title>
<style>
body{{font-family:system-ui,sans-serif;margin:0 auto;padding:16px;max-width:1100px;background:#fff;color:#111}}
table{{border-collapse:collapse;width:100%;display:block;overflow-x:auto}}
td,th{{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}}
tr.rep{{background:#fde8e8}} code{{word-break:break-all}} form{{display:inline}}
textarea,input{{max-width:100%;box-sizing:border-box}}
@media (prefers-color-scheme:dark){{body{{background:#111;color:#eee}}tr.rep{{background:#4a1d1d}}a{{color:#8ab4f8}}}}
</style></head><body><h1>{title}</h1>{body}</body></html>"""

LOGIN_FORM = """<p>{msg}</p><form method="post" action="/admin/login">
<label>Admin-Token <input type="password" name="token" required autocomplete="current-password"></label>
<button>Anmelden</button></form>"""

REPORT_FORM = """<p>{msg}</p><p>Melden Sie hier rechtswidrige Inhalte (Art. 16 DSA).</p>
<form method="post" action="/report">
<p><label>CID des Inhalts<br><input name="cid" required size="64"></label></p>
<p><label>Begründung: Warum ist der Inhalt rechtswidrig?<br>
<textarea name="reason" required minlength="10" maxlength="5000" rows="6" cols="64"></textarea></label></p>
<p><label>Kontakt (optional, für Rückfragen)<br><input name="contact" maxlength="255" size="64"></label></p>
<p><button>Meldung senden</button></p></form>"""


if __name__ == "__main__":
    cmds = {"serve": (serve, 0), "add-user": (add_user, 1), "add-admin": (add_admin, 1),
            "block": (lambda cid: print(f"blocked {cid}, {block(cid)} pin request(s) failed"), 1)}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds or len(sys.argv) - 2 != cmds[sys.argv[1]][1]:
        sys.exit(__doc__)
    fn, _ = cmds[sys.argv[1]]
    fn(*sys.argv[2:])
