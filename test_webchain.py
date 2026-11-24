"""End-to-end test against a fake Kubo RPC. Run: python3 -m unittest -v"""
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TMP = tempfile.mkdtemp()
os.environ["WEBCHAIN_DB"] = os.path.join(TMP, "test.db")
os.environ["WEBCHAIN_DENYLIST"] = os.path.join(TMP, "deny.txt")
os.environ["WEBCHAIN_MAX_PINS"] = "3"

KUBO_PINS = set()
KUBO_FAIL = set()


class FakeKubo(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
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
