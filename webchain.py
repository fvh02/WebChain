#!/usr/bin/env python3
"""WebChain: IPFS pinning service implementing the IPFS Pinning Service API
(https://ipfs.github.io/pinning-services-api-spec/) in front of a Kubo node.

Usage:
  python3 webchain.py serve              start the API server
  python3 webchain.py add-user <name>    create a user, print its API token
  python3 webchain.py block <cid>        takedown: deny-list, unpin, fail all requests
"""
import contextlib
import datetime
import hashlib
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = os.environ.get("WEBCHAIN_DB", "webchain.db")
KUBO = os.environ.get("KUBO_API", "http://127.0.0.1:5001").rstrip("/")
DENYLIST = os.environ.get("WEBCHAIN_DENYLIST", "denylist.txt")
HOST = os.environ.get("WEBCHAIN_HOST", "127.0.0.1")
PORT = int(os.environ.get("WEBCHAIN_PORT", "8080"))
MAX_PINS = int(os.environ.get("WEBCHAIN_MAX_PINS", "1000"))
DELEGATES = [d for d in os.environ.get("WEBCHAIN_DELEGATES", "").split(",") if d]
MAX_BODY = 64 * 1024

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
                old = self.own_pin(con, uid, parts[1])
                con.execute("DELETE FROM pins WHERE requestid=?", (old["requestid"],))
                con.commit()
                unpin_if_unused(old["cid"])
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

    def dispatch(self, method):
        try:
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
    init_db()
    with _deny_lock, open(DENYLIST, "a") as f:
        f.write(cid + "\n")
    with db() as con:
        n = con.execute("UPDATE pins SET status='failed' WHERE cid=?", (cid,)).rowcount
    try:
        kubo("pin/rm", cid)
    except Exception:
        pass
    print(f"blocked {cid}, {n} pin request(s) failed")


if __name__ == "__main__":
    cmds = {"serve": (serve, 0), "add-user": (add_user, 1), "block": (block, 1)}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds or len(sys.argv) - 2 != cmds[sys.argv[1]][1]:
        sys.exit(__doc__)
    fn, _ = cmds[sys.argv[1]]
    fn(*sys.argv[2:])
