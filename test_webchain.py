"""End-to-end test against a fake Kubo RPC. Run: python3 -m unittest -v"""
import io
import json
import re
import os
import tempfile
import threading
import time
import unittest
import zipfile
import uuid
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TMP = tempfile.mkdtemp()
os.environ["WEBCHAIN_DB"] = os.path.join(TMP, "test.db")
os.environ["WEBCHAIN_DENYLIST"] = os.path.join(TMP, "deny.txt")
os.environ["WEBCHAIN_MAX_PINS"] = "3"

KUBO_PINS = set()
KUBO_FAIL = set()
KUBO_ADDS = []
ADD_CID = "bafybeicuvnjaygzunfrxfsrfp7ld3c6w3hhd6wkt4cpvzvxyubmcydhsle"


class FakeKubo(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        if self.path.startswith("/api/v0/add"):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            KUBO_ADDS.append(re.findall(rb'filename="([^"]+)"\r\nContent-Type: ([^\r]+)', body))
            out = json.dumps({"Name": "site", "Hash": ADD_CID}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            return self.wfile.write(out)
        cmd, _, arg = self.path.partition("?arg=")
        if cmd.endswith("pin/add") and arg not in KUBO_FAIL:
            KUBO_PINS.add(arg)
            code = 200
        elif cmd.endswith("pin/rm") and arg in KUBO_PINS:
            KUBO_PINS.discard(arg)
            code = 200
        else:
            code = 500
        self.send_response(code)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")


kubo_srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeKubo)
threading.Thread(target=kubo_srv.serve_forever, daemon=True).start()
os.environ["KUBO_API"] = f"http://127.0.0.1:{kubo_srv.server_port}"

import webchain  # noqa: E402  (env must be set first)

CID1 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
CID2 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
CID3 = "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"


class WebChainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        webchain.init_db()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), webchain.Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"
        cls.alice = cls.make_user("alice")
        cls.bob = cls.make_user("bob")

    @staticmethod
    def make_user(name):
        token = "tok-" + name
        with webchain.db() as con:
            con.execute("INSERT INTO users (name, token_hash) VALUES (?,?)",
                        (name, webchain.token_hash(token)))
        return token

    def call(self, method, path, token=None, body=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def wait_status(self, token, rid, want):
        for _ in range(100):
            code, ps = self.call("GET", f"/pins/{rid}", token)
            if ps["status"] == want:
                return ps
            time.sleep(0.02)
        self.fail(f"status never became {want}: {ps}")

    def test_flow(self):
        self.assertEqual(self.call("GET", "/pins")[0], 401)
        self.assertEqual(self.call("GET", "/pins", "wrong")[0], 401)

        code, ps = self.call("POST", "/pins", self.alice, {"cid": CID1, "name": "site"})
        self.assertEqual(code, 202)
        rid = ps["requestid"]
        self.wait_status(self.alice, rid, "pinned")
        self.assertIn(CID1, KUBO_PINS)

        # list: default filter is status=pinned
        code, lst = self.call("GET", "/pins?name=site", self.alice)
        self.assertEqual((code, lst["count"]), (200, 1))

        # bob cannot see or delete alice's pin
        self.assertEqual(self.call("GET", f"/pins/{rid}", self.bob)[0], 404)
        self.assertEqual(self.call("DELETE", f"/pins/{rid}", self.bob)[0], 404)
        self.assertEqual(self.call("GET", "/pins", self.bob)[1]["count"], 0)

        # bob pins same CID; alice deletes hers; CID stays pinned for bob
        code, bps = self.call("POST", "/pins", self.bob, {"cid": CID1})
        self.wait_status(self.bob, bps["requestid"], "pinned")
        self.assertEqual(self.call("DELETE", f"/pins/{rid}", self.alice), (202, None))
        self.assertIn(CID1, KUBO_PINS)
        self.assertEqual(self.call("DELETE", f"/pins/{bps['requestid']}", self.bob)[0], 202)
        self.assertNotIn(CID1, KUBO_PINS)

    def test_replace(self):
        code, ps = self.call("POST", "/pins", self.alice, {"cid": CID2})
        self.wait_status(self.alice, ps["requestid"], "pinned")
        code, new = self.call("POST", f"/pins/{ps['requestid']}", self.alice, {"cid": CID3})
        self.assertEqual(code, 202)
        self.wait_status(self.alice, new["requestid"], "pinned")
        self.assertEqual(self.call("GET", f"/pins/{ps['requestid']}", self.alice)[0], 404)
        self.assertNotIn(CID2, KUBO_PINS)
        self.call("DELETE", f"/pins/{new['requestid']}", self.alice)

    def test_validation_quota_failure_block(self):
        for bad in ({"cid": "not-a-cid"}, {"cid": CID1, "name": 5}, {"cid": CID1, "meta": {"a": 1}}, []):
            self.assertEqual(self.call("POST", "/pins", self.bob, bad)[0], 400, bad)
        self.assertEqual(self.call("GET", "/pins?status=bogus", self.bob)[0], 400)

        KUBO_FAIL.add(CID3)
        code, ps = self.call("POST", "/pins", self.bob, {"cid": CID3})
        self.wait_status(self.bob, ps["requestid"], "failed")
        KUBO_FAIL.discard(CID3)

        rids = [self.call("POST", "/pins", self.bob, {"cid": CID2})[1]["requestid"] for _ in range(3)]
        self.assertEqual(self.call("POST", "/pins", self.bob, {"cid": CID1})[0], 429)
        for rid in rids:
            self.wait_status(self.bob, rid, "pinned")

        webchain.block(CID2)
        self.assertNotIn(CID2, KUBO_PINS)
        self.assertEqual(self.call("GET", f"/pins/{rids[0]}", self.bob)[1]["status"], "failed")
        code, err = self.call("POST", "/pins", self.bob, {"cid": CID2})
        self.assertEqual((code, err["error"]["reason"]), (403, "CONTENT_BLOCKED"))


if __name__ == "__main__":
    unittest.main()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class AdminWebTest(unittest.TestCase):
    base = None

    @classmethod
    def setUpClass(cls):
        webchain.init_db()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), webchain.Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"
        cls.admin_token = "admin-tok"
        with webchain.db() as con:
            con.execute("INSERT OR IGNORE INTO users (name, token_hash) VALUES ('carol', 'x')")
            con.execute("INSERT OR IGNORE INTO admins VALUES (?,?)", (webchain.token_hash(cls.admin_token), "root"))

    def req(self, method, path, form=None, cookie=None, origin=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method)
        if cookie:
            r.add_header("Cookie", cookie)
        if origin:
            r.add_header("Origin", origin)
        try:
            with OPENER.open(r) as resp:
                return resp.status, resp.headers, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode()

    def login(self):
        code, h, _ = self.req("POST", "/admin/login", {"token": self.admin_token})
        self.assertEqual(code, 303)
        return h["Set-Cookie"].split(";")[0]

    def test_report_search_remove_reject(self):
        cid_a = "bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        cid_b = "bafybeie5gq4jxvzmsym6hjlwxej4rwdoxt7wadqvmmwbqi7r27fclha2va"
        with webchain.db() as con:
            uid = con.execute("SELECT id FROM users WHERE name='carol'").fetchone()[0]
            for cid, name in ((cid_a, "<script>x</script>"), (cid_b, "harmlos")):
                con.execute("INSERT INTO pins VALUES (?,?,?,?,'[]','{}','pinned',?)",
                            (cid + "-r", uid, cid, name, time.time()))
        KUBO_PINS.update({cid_a, cid_b})

        # public report form
        self.assertEqual(self.req("POST", "/report", {"cid": "nope", "reason": "x"})[0], 400)
        for cid in (cid_a, cid_b):
            self.assertEqual(self.req("POST", "/report", {"cid": cid, "reason": "rechtswidriger Inhalt"})[0], 200)

        # admin pages need login
        code, _, body = self.req("GET", "/admin")
        self.assertIn('name="token"', body)
        self.assertEqual(self.req("POST", "/admin/remove", {"cid": cid_a})[0], 303)
        self.assertIn(cid_a, KUBO_PINS)
        self.assertEqual(self.req("POST", "/admin/login", {"token": "wrong"})[0], 401)

        cookie = self.login()
        code, _, body = self.req("GET", "/admin?q=carol", cookie=cookie)
        self.assertEqual(code, 200)
        self.assertIn("Offene Meldungen (2)", body)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>x", body)

        # cross-site POST rejected
        code, _, _ = self.req("POST", "/admin/remove", {"cid": cid_a}, cookie, origin="https://evil.example")
        self.assertEqual(code, 403)
        self.assertIn(cid_a, KUBO_PINS)

        # remove reported content
        self.assertEqual(self.req("POST", "/admin/remove", {"cid": cid_a}, cookie)[0], 303)
        self.assertNotIn(cid_a, KUBO_PINS)
        self.assertEqual(self.call_status(cid_a), "failed")

        # reject the other report: content stays
        with webchain.db() as con:
            rid = con.execute("SELECT id FROM reports WHERE cid=?", (cid_b,)).fetchone()[0]
        self.assertEqual(self.req("POST", "/admin/reject", {"id": rid}, cookie)[0], 303)
        self.assertIn(cid_b, KUBO_PINS)
        self.assertIn("Offene Meldungen (0)", self.req("GET", "/admin", cookie=cookie)[2])

        # logout kills the session
        self.req("POST", "/admin/logout", {}, cookie)
        self.assertIn('name="token"', self.req("GET", "/admin", cookie=cookie)[2])

    def call_status(self, cid):
        with webchain.db() as con:
            return con.execute("SELECT status FROM pins WHERE cid=?", (cid,)).fetchone()[0]


class AccountWebTest(AdminWebTest):
    """User portal: login with API token, upload ZIP, pin by CID, delete."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.user_token = "dave-tok"
        with webchain.db() as con:
            con.execute("INSERT INTO users (name, token_hash) VALUES ('dave', ?)",
                        (webchain.token_hash(cls.user_token),))

    def upload(self, cookie, filename, data, name="meine-seite"):
        b = uuid.uuid4().hex
        body = (f'--{b}\r\nContent-Disposition: form-data; name="name"\r\n\r\n{name}\r\n'
                f'--{b}\r\nContent-Disposition: form-data; name="site"; filename="{filename}"\r\n'
                f'Content-Type: application/zip\r\n\r\n').encode() + data + f"\r\n--{b}--\r\n".encode()
        r = urllib.request.Request(self.base + "/account/upload", data=body, method="POST",
                                   headers={"Content-Type": f"multipart/form-data; boundary={b}",
                                            "Cookie": cookie})
        try:
            with OPENER.open(r) as resp:
                return resp.status, resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.headers

    def test_report_search_remove_reject(self):
        pass  # covered by AdminWebTest

    def test_account(self):
        self.assertIn('action="/account/login"', self.req("GET", "/account")[2])
        self.assertEqual(self.req("POST", "/account/login", {"token": "admin-tok"})[0], 401)
        code, h, _ = self.req("POST", "/account/login", {"token": self.user_token})
        self.assertEqual(code, 303)
        cookie = h["Set-Cookie"].split(";")[0]
        self.assertIn("Path=/account", h["Set-Cookie"])

        # ZIP of a folder: top folder stripped, parent dirs sent before files
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("meine-seite/index.html", "<h1>Hallo</h1>")
            z.writestr("meine-seite/css/style.css", "h1{}")
        code, h = self.upload(cookie, "seite.zip", buf.getvalue())
        self.assertEqual(code, 303)
        self.assertIn(ADD_CID, urllib.parse.unquote_plus(h["Location"]))
        self.assertEqual([n for n, _ in KUBO_ADDS[-1]], [b"site", b"site%2Fcss", b"site%2Fcss%2Fstyle.css",
                                                          b"site%2Findex.html"])
        self.assertEqual(KUBO_ADDS[-1][0][1], b"application/x-directory")
        for _ in range(100):
            if ADD_CID in KUBO_PINS:
                break
            time.sleep(0.02)
        self.assertIn(ADD_CID, KUBO_PINS)
        page = self.req("GET", "/account", cookie=cookie)[2]
        self.assertIn("meine-seite", page)
        self.assertIn(f"https://dweb.link/ipfs/{ADD_CID}/", page)

        # bad uploads
        bad = io.BytesIO()
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr("../evil.html", "x")
        for data in (b"not a zip", bad.getvalue()):
            code, h = self.upload(cookie, "x.zip", data)
            self.assertEqual(code, 303)
            self.assertNotIn("Hochgeladen", urllib.parse.unquote_plus(h["Location"]))

        # cross-site upload rejected
        self.assertEqual(self.req("POST", "/account/pin", {"cid": CID3}, cookie, "https://evil.example")[0], 403)

        # admin cookie path does not grant account access and vice versa
        self.assertIn('action="/admin/login"', self.req("GET", "/admin", cookie=cookie)[2])

        # delete own pin; another user's requestid is ignored
        with webchain.db() as con:
            rid = con.execute("SELECT requestid FROM pins WHERE cid=?", (ADD_CID,)).fetchone()[0]
            foreign = con.execute("SELECT requestid FROM pins WHERE user_id!=(SELECT id FROM users WHERE name='dave')"
                                  " AND status!='failed' LIMIT 1").fetchone()
        if foreign:
            self.req("POST", "/account/delete", {"requestid": foreign[0]}, cookie)
            with webchain.db() as con:
                self.assertIsNotNone(con.execute("SELECT 1 FROM pins WHERE requestid=?", (foreign[0],)).fetchone())
        self.assertEqual(self.req("POST", "/account/delete", {"requestid": rid}, cookie)[0], 303)
        self.assertNotIn(ADD_CID, KUBO_PINS)
