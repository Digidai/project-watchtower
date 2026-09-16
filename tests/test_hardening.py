import contextlib
import http.client
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
import urllib.error
from unittest.mock import patch

from watchtower.dashboard_server import AuthState, BoundedServer, COOKIE, make_handler
from watchtower.cli import (
    bounded_github_detail_limit,
    build_dashboard_findings,
    collect_xray_config_check,
    github_http_error_metadata,
    render_dashboard,
)

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "ops" / (name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class AuthTests(unittest.TestCase):
    def test_atomic_reports_preserve_open_readers_and_failed_writes(self):
        from watchtower.cli import atomic_write_text
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.html"
            atomic_write_text(path, "old complete page")
            with path.open() as reader:
                atomic_write_text(path, "new complete page")
                self.assertEqual(reader.read(), "old complete page")
            self.assertEqual(path.read_text(), "new complete page")
            with patch("watchtower.cli.os.replace", side_effect=OSError("test disk error")):
                with self.assertRaises(OSError):
                    atomic_write_text(path, "not committed")
            self.assertEqual(path.read_text(), "new complete page")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_fail_closed(self):
        with self.assertRaises(ValueError):
            AuthState("", "s" * 40)
        with self.assertRaises(ValueError):
            AuthState("test", "")

    def test_expiry_revocation_and_randomness(self):
        now = [0]
        auth = AuthState("test", "s" * 40, ttl=10, clock=lambda: now[0])
        _, first = auth.login("127.0.0.1", "test")
        _, second = auth.login("127.0.0.1", "test")
        self.assertNotEqual(first, second)
        auth.revoke(first)
        self.assertFalse(auth.authenticate(first))
        self.assertTrue(auth.authenticate(second))
        now[0] = 11
        self.assertFalse(auth.authenticate(second))

    def test_rate_limit_and_window(self):
        now = [0]
        auth = AuthState("test", "s" * 40, clock=lambda: now[0])
        for _ in range(5):
            self.assertEqual(auth.login("127.0.0.1", "wrong")[0], 401)
        self.assertEqual(auth.login("127.0.0.1", "test")[0], 429)
        now[0] = 901
        self.assertEqual(auth.login("127.0.0.1", "test")[0], 303)

    def test_http_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "index.html").write_text("private-status")
            auth = AuthState("test", "s" * 40)
            server = BoundedServer(("127.0.0.1", 0), make_handler(directory, auth, lambda error=False: "locked", "https://oracle.syncany.app"))
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            def request(method, path, body=None, headers=None):
                conn = http.client.HTTPConnection(*server.server_address, timeout=3)
                conn.request(method, path, body, headers or {})
                response = conn.getresponse()
                result = response.status, dict(response.getheaders()), response.read().decode()
                conn.close()
                return result
            try:
                self.assertEqual(request("GET", "/latest.json")[0], 403)
                trusted = {"X-Watchtower-Origin": "s" * 40, "X-Forwarded-Proto": "https", "X-Watchtower-Client-IP": "127.0.0.1"}
                self.assertEqual(request("GET", "/latest.json", headers=trusted)[2], "locked")
                self.assertEqual(request("POST", "/login", "password=test", trusted)[0], 403)
                trusted["Origin"] = "https://oracle.syncany.app"
                status, headers, _ = request("POST", "/login", "password=test", trusted)
                self.assertEqual(status, 303)
                cookie = headers["Set-Cookie"]
                for flag in ("Secure", "HttpOnly", "SameSite=Strict"):
                    self.assertIn(flag, cookie)
                trusted["Cookie"] = cookie.split(";")[0]
                self.assertEqual(request("GET", "/", headers=trusted)[2], "private-status")
                self.assertEqual(request("GET", "/../../etc/passwd", headers=trusted)[0], 404)
                request("GET", "/logout", headers=trusted)
                self.assertEqual(request("GET", "/", headers=trusted)[2], "locked")
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)


class DashboardFindingTests(unittest.TestCase):
    @staticmethod
    def report(mode, *, repositories=None, urls=None, github_checks=None, self_checks=None):
        return {
            "run": {"mode": mode, "completed_at": "2026-09-01T00:00:00Z"},
            "summary": {
                "status": "warn",
                "url_count": len(urls or []),
                "slow_url_ms": 8000,
                "repo_check_count": len(github_checks or []),
                "self_check_count": len(self_checks or []),
            },
            "repositories": repositories or [],
            "urls": urls or [],
            "github_repo_checks": github_checks or [],
            "self_checks": self_checks or [],
            "github": {},
            "resource_budget": {"bytes_read": 0},
            "system": {},
        }

    def test_deduplicates_url_and_workflow_across_modes(self):
        repo = {"name": "raltic", "fork": False, "archived": False}
        failed_url = {
            "url": "https://old.example.workers.dev",
            "source": "repo_homepage",
            "repo": "raltic",
            "critical": False,
            "ok": False,
            "status": 404,
            "error": "http 404",
        }
        check_one = {
            "repo": "venturedex-co",
            "kind": "workflow",
            "ok": False,
            "status": "failure",
            "detail": "Sync VentureDex launches",
            "url": "https://github.com/Digidai/venturedex-co/actions/runs/1",
        }
        check_two = dict(check_one, url="https://github.com/Digidai/venturedex-co/actions/runs/2")
        reports = {
            "github-lite": self.report("github-lite", repositories=[repo], urls=[failed_url], github_checks=[check_one]),
            "daily": self.report("daily", repositories=[repo], urls=[failed_url], github_checks=[check_two]),
        }

        findings = build_dashboard_findings(reports, ["github-lite", "daily"])

        self.assertEqual(len(findings), 2)
        self.assertTrue(all(item["category"] == "action" for item in findings))
        self.assertTrue(all(item["occurrences"] == 2 for item in findings))
        self.assertTrue(all(item["modes"] == ["github-lite", "daily"] for item in findings))

    def test_owned_homepage_is_action_and_fork_is_observation(self):
        repositories = [
            {"name": "raltic", "fork": False, "archived": False},
            {"name": "ChatChat", "fork": True, "archived": False},
        ]
        urls = [
            {"url": "https://raltic.invalid/", "source": "repo_homepage", "repo": "raltic", "ok": False},
            {"url": "https://chat.invalid/", "source": "repo_homepage", "repo": "ChatChat", "ok": False},
        ]
        findings = build_dashboard_findings(
            {"daily": self.report("daily", repositories=repositories, urls=urls)},
            ["daily"],
        )
        categories = {item["title"].split()[0]: item["category"] for item in findings}
        self.assertEqual(categories, {"raltic": "action", "ChatChat": "observation"})

    def test_external_certificate_warning_is_visible_without_core_alarm(self):
        url = {
            "url": "https://paper.design/",
            "source": "venturedex_company",
            "repo": "Paper",
            "critical": False,
            "ok": True,
            "status": 200,
            "elapsed_ms": 320,
            "tls_days_remaining": 25,
        }
        report = self.report("venture-check", urls=[url])
        report["summary"]["cert_warning_count"] = 1
        with tempfile.TemporaryDirectory() as directory:
            rendered = render_dashboard(Path(directory), report)
        self.assertIn("Core healthy", rendered)
        self.assertIn("No actionable problems", rendered)
        self.assertIn("paper.design", rendered)
        self.assertIn("TLS certificate has 25 days remaining", rendered)

    def test_unauthenticated_github_budget_preserves_rate_limit_reserve(self):
        self.assertEqual(bounded_github_detail_limit(8, False, "60", 8), 8)
        self.assertEqual(bounded_github_detail_limit(8, False, "11", 8), 3)
        self.assertEqual(bounded_github_detail_limit(8, False, "0", 8), 0)
        self.assertEqual(bounded_github_detail_limit(16, True, "0", 8), 16)

    def test_github_rate_limit_error_keeps_reset_metadata(self):
        exc = urllib.error.HTTPError(
            "https://api.github.com/users/Digidai/repos",
            403,
            "rate limit exceeded",
            {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1789533953"},
            None,
        )
        self.addCleanup(exc.close)
        metadata = github_http_error_metadata(exc, authenticated=False)
        self.assertEqual(metadata["rate_limit_remaining"], "0")
        self.assertEqual(metadata["rate_limit_reset"], "1789533953")
        self.assertIn("resets at", metadata["error"])


class ProxyTests(unittest.TestCase):
    def test_hy2_has_soft_backend_dependency(self):
        import configparser
        unit = configparser.ConfigParser()
        unit.read(ROOT / "ops/hysteria2-surge-test.service")
        self.assertIn("xray-vless-global.service", unit["Unit"]["Wants"])
        self.assertNotIn("xray-vless-global.service", unit["Unit"].get("Requires", ""))
        deploy = (ROOT / "scripts/deploy.sh").read_text()
        self.assertIn("cloudflared-watchtower hysteria2-surge-test", deploy)

    def test_deploy_publishes_proxy_status_before_self_smoke(self):
        deploy = (ROOT / "scripts/deploy.sh").read_text()
        publish = deploy.index("sudo systemctl start watchtower-proxy-status.service")
        self_smoke = deploy.index("self_smoke=", publish)
        self.assertLess(publish, self_smoke)

    def test_failed_installed_exit_rolls_back_private_config(self):
        sync = module("equaldcdn_sync")
        node = {"server": "1.1.1.1", "port": 443, "uuid": "fake", "reality-opts": {"public-key": "key"}}
        old = {"outbounds": [sync.outbound(dict(node, server="8.8.8.8"))]}
        temporary_directory = tempfile.TemporaryDirectory
        with temporary_directory() as directory:
            root = Path(directory)
            sync.TARGET, sync.STATE, sync.SECRET = root / "config.json", root / "state.json", root / "secret.json"
            sync.write_json(sync.TARGET, old)
            sync.write_json(sync.SECRET, {"url": "not-sent", "expected_ip": "exit"})
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(sync, "fetch", return_value="fixture"))
                stack.enter_context(patch.object(sync, "parse_nodes", return_value=[node]))
                stack.enter_context(patch.object(sync, "choose", return_value=(node, "verified-failover")))
                stack.enter_context(patch.object(sync, "probe", return_value=False))
                stack.enter_context(patch.object(sync, "log"))
                restart = stack.enter_context(patch.object(sync, "restart"))
                stack.enter_context(patch.object(sync.subprocess, "run", return_value=SimpleNamespace(returncode=0)))
                stack.enter_context(patch.object(sync.tempfile, "TemporaryDirectory", side_effect=lambda **_: temporary_directory(dir=root)))
                self.assertEqual(sync.main(), 1)
            self.assertEqual(restart.call_count, 2)
            self.assertEqual(json.loads(sync.TARGET.read_text()), old)
            self.assertEqual(sync.TARGET.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(sync.STATE.read_text())["last_error"], "RuntimeError")

    def test_status_freshness_and_permissions_are_enforced(self):
        from watchtower.cli import collect_sync_health_checks
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "health.json"
            path.write_text(json.dumps({"generated_at": 1000, "last_success": 1000,
                "credentials_private": True, "switches_24h": 0}))
            with patch("watchtower.cli.time.time", return_value=1100):
                self.assertTrue(all(c.ok for c in collect_sync_health_checks({"self_sync_health_path": str(path)})))
            with patch("watchtower.cli.time.time", return_value=10000):
                checks = collect_sync_health_checks({"self_sync_health_path": str(path)})
                self.assertTrue(any(c.status == "fail" for c in checks))

    def test_xray_config_matches_verified_sync_server(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "xray.json"
            status_path = root / "health.json"
            config_path.write_text(json.dumps({"outbounds": [
                {"tag": "exclusive-static-residential", "settings": {"vnext": [
                    {"address": "23.148.204.153", "port": 42892}
                ]}},
                {"tag": "direct"},
                {"tag": "block"},
            ]}))
            status_path.write_text(json.dumps({"server": "23.148.204.153"}))
            policy = {"self_xray_config": {
                "path": str(config_path),
                "expected_outbound_tags": ["exclusive-static-residential", "direct", "block"],
                "exclusive_tag": "exclusive-static-residential",
                "expected_server_status_path": str(status_path),
                "expected_port": 42892,
                "forbidden_terms": ["relay-out", "dialerProxy"],
            }}

            self.assertTrue(collect_xray_config_check(policy)[0].ok)
            status_path.write_text(json.dumps({"server": "23.148.204.143"}))
            self.assertFalse(collect_xray_config_check(policy)[0].ok)

    def test_atomic_credentials_are_private(self):
        sync = module("equaldcdn_sync")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config.json"
            sync.write_json(target, {"version": 1})
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            sync.write_json(target, {"version": 2})
            self.assertEqual(json.loads(target.read_text()), {"version": 2})

    def test_subscription_redirect_rejects_non_https_and_cross_host(self):
        sync = module("equaldcdn_sync")
        for url in ("http://equaldcdn.com/", "https://example.com/", "https://127.0.0.1/"):
            with self.assertRaises(ValueError):
                sync.SameHostRedirect().redirect_request(None, None, 302, "", {}, url)

    def test_sanitizer_removes_credentials_but_keeps_route_alarms(self):
        source = {"inbounds": [{"protocol": "trojan", "settings": {"clients": [{"password": "secret"}]}}],
                  "outbounds": [{"tag": "relay-out", "settings": {"vnext": [{"address": "1.1.1.1", "users": [{"id": "secret"}]}]}, "streamSettings": {"sockopt": {"dialerProxy": "relay"}}}]}
        result = module("proxy_status").sanitize(source)
        self.assertNotIn("secret", json.dumps(result))
        self.assertIn("dialerProxy", json.dumps(result))
        self.assertEqual(result["outbounds"][0]["tag"], "relay-out")

    def test_healthy_current_never_switches_for_speed(self):
        sync = module("equaldcdn_sync")
        node = {"server": "1.1.1.1", "port": 443, "uuid": "fake", "reality-opts": {"public-key": "key"}}
        alternate = dict(node, server="8.8.8.8")
        current = {"outbounds": [sync.outbound(node)]}
        with patch.object(sync, "probe", return_value=True):
            selected, reason = sync.choose([alternate, node], current, "exit", lambda _: self.fail("unnecessary candidate probe"))
        self.assertEqual(selected, node)
        self.assertEqual(reason, "healthy-current")

    def test_failover_requires_live_probe(self):
        sync = module("equaldcdn_sync")
        node = {"server": "1.1.1.1", "port": 443, "uuid": "fake", "reality-opts": {"public-key": "key"}}
        with patch.object(sync, "probe", return_value=False):
            with self.assertRaises(RuntimeError):
                sync.choose([node], {"outbounds": [sync.outbound(node)]}, "exit", lambda _: False)


class WorkflowTests(unittest.TestCase):
    def test_actual_retry_script_exit_codes(self):
        source = (ROOT / ".github/workflows/watchtower.yml").read_text()
        source = source[source.index('          : "${WATCHTOWER_HOST'):]
        source = "\n".join(line[10:] for line in source.splitlines())
        source = source.replace("${{ steps.mode.outputs.mode }}", "core")
        cases = [("return 255", 255), ("printf '%s' '{\"summary\":{\"status\":\"fail\"}}'", 1),
                 ("printf '%s' '{\"summary\":{\"status\":\"ok\"}}'", 0),
                 ("printf '%s' '{\"status\":\"busy\"}'", 75)]
        with tempfile.TemporaryDirectory() as directory:
            for stub, expected in cases:
                prefix = 'WATCHTOWER_HOST=invalid WATCHTOWER_USER=test\nsleep() { :; }\nssh() { ' + stub + '; }\n'
                result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", prefix + source], cwd=directory, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
