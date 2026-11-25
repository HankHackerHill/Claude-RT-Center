"""Unit tests for Stage 1 tooling: manager-conf generation, secret generation, TLS client, Gate 1 helpers.
Stdlib only, no services. The TLS tests mint a throwaway CA with the openssl CLI (skipped if it is missing).

  python3 -I tests/test_stack.py
"""
import json
import os
import pathlib
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

R = pathlib.Path(__file__).resolve().parent.parent
sys.path[:0] = [str(R / "cc"), str(R / "scripts")]
import gen_manager_conf as G  # noqa: E402
import gen_secrets as S  # noqa: E402
import indexer as I  # noqa: E402
import indexer_roles as RO  # noqa: E402
import verify as V  # noqa: E402

UPSTREAM = """<ossec_config>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
</ossec_config>
"""


class ManagerConf(unittest.TestCase):
    snippet = (R / "wazuh" / "cc_localfile.conf").read_text()

    def test_inserts_rule_dir_inside_existing_ruleset(self):
        out = re.sub(r"<!--.*?-->", "", G.build_manager_conf(UPSTREAM, self.snippet), flags=re.S)
        rs = out[out.index("<ruleset>"):out.index("</ruleset>")]
        self.assertIn("<rule_dir>etc/cc-rules</rule_dir>", rs)
        self.assertIn("<rule_dir>ruleset/rules</rule_dir>", rs)       # built-ins kept
        self.assertEqual(out.count("<ruleset>"), 1)                    # never a second <ruleset> (it replaces)
        self.assertIn("/var/log/cc-suricata/eve.json", out)

    def test_idempotent(self):
        once = G.build_manager_conf(UPSTREAM, self.snippet)
        self.assertEqual(G.build_manager_conf(once, self.snippet), once)

    def test_rejects_unexpected_upstream_shape(self):
        with self.assertRaises(ValueError):
            G.build_manager_conf("<ossec_config/>", self.snippet)
        with self.assertRaises(ValueError):
            G.build_manager_conf(UPSTREAM + UPSTREAM, self.snippet)

    def test_snippet_has_no_ruleset_block(self):
        self.assertNotIn("<ruleset>", self.snippet.split("-->", 1)[1])

    def test_real_upstream_if_cloned(self):
        up = R / "wazuh-docker" / "single-node" / "config" / "wazuh_cluster" / "wazuh_manager.conf"
        if not up.exists():
            self.skipTest("wazuh-docker not cloned")
        out = G.build_manager_conf(up.read_text(), self.snippet)
        self.assertEqual(out.count("<rule_dir>etc/cc-rules</rule_dir>"), 1)


class Secrets(unittest.TestCase):
    def test_fill_env_generates_only_empty_and_forces_reader(self):
        n = iter(f"Gen{i:02d}xxxxxxxxxxxxxxxxAa1." for i in range(10))
        text, changed = S.fill_env("WAZUH_ADMIN_PASS=\nWAZUH_API_PASS=keepme-keepme-keep1A.\nINDEXER_USER=admin\n# c\n",
                                   gen=lambda: next(n))
        env = S.parse_env(text)
        self.assertTrue(env["WAZUH_ADMIN_PASS"].startswith("Gen"))
        self.assertEqual(env["WAZUH_API_PASS"], "keepme-keepme-keep1A.")
        self.assertEqual(env["INDEXER_USER"], "cc_reader")
        self.assertIn("WAZUH_KIBANASERVER_PASS", env)                  # appended when absent
        self.assertIn("INDEXER_PASS", env)
        self.assertNotIn("WAZUH_API_PASS", changed)

    def test_generated_password_meets_policy(self):
        for _ in range(50):
            p = S.new_password()
            S.check_secret("x", p)
            self.assertTrue(any(c.isupper() for c in p) and any(c.islower() for c in p)
                            and any(c.isdigit() for c in p) and any(not c.isalnum() for c in p))

    def test_defaults_and_unsafe_rejected(self):
        for bad in ("SecretPassword", "MyS3cr37P450r.*-", "short", 'has"quote-long-enough-x', "x" * 80):
            with self.assertRaises(ValueError):
                S.check_secret("x", bad)

    def test_internal_users_only_needed_users(self):
        h = "$2y$12$" + "a" * 53
        y = S.render_internal_users({"admin": h, "kibanaserver": h, "cc_reader": h})
        for demo in ("kibanaro", "logstash", "readall:", "snapshotrestore"):
            self.assertNotIn(demo, y)
        self.assertIn("cc_reader:", y)
        cc = y[y.index("cc_reader:"):]
        self.assertIn("backend_roles: []", cc)                         # no implicit privileges
        with self.assertRaises(ValueError):
            S.render_internal_users({"admin": "plain", "kibanaserver": h, "cc_reader": h})

    def test_dashboard_yml(self):
        y = S.render_dashboard_wazuh_yml("Abcdefghijklmnop1.")
        self.assertIn('password: "Abcdefghijklmnop1."', y)
        self.assertIn("1513629884013", y)                              # same host id upstream uses
        with self.assertRaises(ValueError):
            S.render_dashboard_wazuh_yml("MyS3cr37P450r.*-")


class Roles(unittest.TestCase):
    def test_role_is_read_only_and_scoped(self):
        b = RO.role_body()
        self.assertEqual(b["cluster_permissions"], ["cluster:monitor/health"])
        self.assertEqual(b["index_permissions"], [{"index_patterns": ["wazuh-alerts-*"], "allowed_actions": ["read"]}])
        self.assertEqual(RO.mapping_body()["users"], ["cc_reader"])


def _openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI needed to mint a test CA")
class PinnedTLS(unittest.TestCase):
    """The CC indexer client against a local TLS server: right name + CA works, anything else fails."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cc-tls-")
        d = cls.d
        for ca in ("ca", "evil"):
            # like wazuh-docker's root: CA:TRUE but no keyUsage (Python 3.13 strict mode rejects that by default)
            _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{ca}.key", "-out", f"{ca}.pem",
                     "-days", "2", "-subj", f"/CN={ca}", "-addext", "basicConstraints=critical,CA:TRUE", cwd=d)
        pathlib.Path(d, "ext").write_text("subjectAltName=DNS:wazuh.indexer\n")
        for name, ca in (("srv", "ca"), ("evilsrv", "evil")):
            _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
                     "-subj", "/CN=wazuh.indexer", cwd=d)
            _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", f"{ca}.pem", "-CAkey", f"{ca}.key",
                     "-CAcreateserial", "-out", f"{name}.pem", "-days", "2", "-extfile", "ext", cwd=d)
        cls.servers = {}
        for name in ("srv", "evilsrv"):
            class H(BaseHTTPRequestHandler):
                def do_GET(self):  # noqa: N802
                    b = json.dumps({"status": "green", "auth": self.headers.get("Authorization", "")}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)

                def log_message(self, *a):
                    pass
            srv = HTTPServer(("127.0.0.1", 0), H)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(f"{d}/{name}.pem", f"{d}/{name}.key")
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            cls.servers[name] = srv

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers.values():
            s.shutdown()
        shutil.rmtree(cls.d, ignore_errors=True)

    def client(self, server, host="wazuh.indexer", ca="ca"):
        port = self.servers[server].server_address[1]
        os.environ.update(INDEXER_URL=f"https://{host}:{port}", INDEXER_CONNECT="127.0.0.1", INDEXER_USER="u",
                          INDEXER_PASS="p", INDEXER_CA=f"{self.d}/{ca}.pem", HTTPS_PROXY="http://127.0.0.1:9")
        return I.Indexer()

    def test_right_name_and_ca_ok_and_no_proxy_used(self):
        self.assertEqual(self.client("srv").health(), "green")          # HTTPS_PROXY points nowhere: not used

    def test_wrong_name_rejected(self):
        self.assertIn("Hostname mismatch", self.client("srv", host="localhost").health())

    def test_foreign_ca_rejected(self):
        self.assertIn("CERTIFICATE_VERIFY_FAILED", self.client("evilsrv").health())

    def test_context_is_verifying(self):
        ctx = I.tls_context(pathlib.Path(self.d, "ca.pem"))
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_plain_http_and_missing_ca_refused(self):
        os.environ.update(INDEXER_URL="http://wazuh.indexer:9200", INDEXER_USER="u", INDEXER_PASS="p")
        with self.assertRaises(I.IndexerError):
            I.Indexer()
        os.environ.update(INDEXER_URL="https://wazuh.indexer:9200", INDEXER_CA="/nonexistent.pem")
        with self.assertRaises(I.IndexerError):
            I.Indexer()


class GateHelpers(unittest.TestCase):
    def test_off_range_packets(self):
        now = time.time()
        ts = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".000000+0000"
        lines = [
            {"timestamp": ts(now + 1), "event_type": "flow", "src_ip": "172.30.0.10", "dest_ip": "172.30.0.1", "dest_port": 9200},
            {"timestamp": ts(now + 1), "event_type": "flow", "src_ip": "172.30.0.10", "dest_ip": "1.1.1.1", "dest_port": 443},
            {"timestamp": ts(now + 1), "event_type": "http", "src_ip": "172.30.0.10", "dest_ip": "172.30.0.20", "dest_port": 3000},
            {"timestamp": ts(now + 1), "event_type": "flow", "src_ip": "172.30.0.10", "dest_ip": "224.0.0.251", "dest_port": 5353},
            {"timestamp": ts(now - 100), "event_type": "flow", "src_ip": "172.30.0.10", "dest_ip": "8.8.8.8", "dest_port": 53},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            # both Suricata's compact form and a spaced form must be scanned (a whitespace-dependent prefilter
            # once made this check pass vacuously)
            f.write("\n".join(json.dumps(x, separators=(",", ":")) if i % 2 else json.dumps(x)
                              for i, x in enumerate(lines)) + "\nnot json\n")
        old, V.EVE = V.EVE, pathlib.Path(f.name)
        try:
            got = V.off_range_packets(now)
        finally:
            V.EVE = old
            os.unlink(f.name)
        self.assertEqual(sorted(got), ["flow 172.30.0.10->1.1.1.1:443", "flow 172.30.0.10->172.30.0.1:9200"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
