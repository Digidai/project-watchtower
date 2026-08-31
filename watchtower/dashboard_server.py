"""Bounded, authenticated dashboard behind a trusted encrypted tunnel."""
from __future__ import annotations

from collections import deque
import hmac
import http.cookies
import http.server
import ipaddress
import secrets
import threading
import time
import urllib.parse
from pathlib import Path
import re

COOKIE = "__Host-watchtower"


class AuthState:
    def __init__(self, password, origin_secret, ttl=28800, clock=time.monotonic):
        if not password or len(origin_secret) < 32:
            raise ValueError("Dashboard password and trusted origin secret are required")
        self.password = password.encode()
        self.origin_secret = origin_secret.encode()
        self.ttl = ttl
        self.clock = clock
        self.sessions = {}
        self.attempts = {}
        self.global_attempts = deque()
        self.lock = threading.Lock()

    def trusted(self, headers):
        return (headers.get("X-Forwarded-Proto") == "https" and
                hmac.compare_digest(headers.get("X-Watchtower-Origin", "").encode(), self.origin_secret))

    def authenticate(self, token):
        with self.lock:
            expiry = self.sessions.get(token, 0)
            if expiry <= self.clock():
                self.sessions.pop(token, None)
                return False
            return True

    def revoke(self, token):
        with self.lock:
            self.sessions.pop(token, None)

    def login(self, client_ip, submitted):
        with self.lock:
            now = self.clock()
            self.sessions = {k: v for k, v in self.sessions.items() if v > now}
            self.attempts = {k: deque(t for t in v if t > now - 900)
                             for k, v in self.attempts.items() if v and v[-1] > now - 900}
            while self.global_attempts and self.global_attempts[0] <= now - 900:
                self.global_attempts.popleft()
            attempts = self.attempts.setdefault(client_ip, deque())
            if len(attempts) >= 5 or len(self.global_attempts) >= 120 or len(self.attempts) > 1024:
                return 429, None
            attempts.append(now)
            self.global_attempts.append(now)
            if not hmac.compare_digest(submitted.encode(), self.password):
                return 401, None
            if len(self.sessions) >= 128:
                self.sessions.pop(next(iter(self.sessions)))
            token = secrets.token_urlsafe(32)
            self.sessions[token] = now + self.ttl
            return 303, token


class BoundedServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def make_handler(directory, auth, locked_page, public_origin):
    directory = Path(directory).resolve()

    class Handler(http.server.SimpleHTTPRequestHandler):
        server_version = "Watchtower"
        sys_version = ""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(directory), **kwargs)

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def cookie_token(self):
            jar = http.cookies.SimpleCookie()
            try:
                jar.load(self.headers.get("Cookie", ""))
                return jar[COOKIE].value if COOKIE in jar else ""
            except http.cookies.CookieError:
                return ""

        def trusted(self):
            if auth.trusted(self.headers):
                return True
            self.send_error(403, "Trusted HTTPS entry required")
            return False

        def locked(self, status=200, error=False, head=False):
            body = locked_page(error=error).encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if status == 429:
                self.send_header("Retry-After", "900")
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def redirect(self, token, max_age):
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"{COOKIE}={token}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            if not self.trusted():
                return
            if self.headers.get("Origin") != public_origin:
                self.send_error(403, "Origin rejected")
                return
            path = urllib.parse.urlsplit(self.path).path
            if path != "/login":
                self.send_error(404)
                return
            if self.headers.get("Transfer-Encoding"):
                self.send_error(400)
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if not 0 <= length <= 4096:
                self.send_error(413)
                return
            fields = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
            client_ip = self.headers.get("X-Watchtower-Client-IP", "")
            try:
                client_ip = str(ipaddress.ip_address(client_ip))
            except ValueError:
                self.send_error(400)
                return
            status, token = auth.login(client_ip, fields.get("password", [""])[0])
            if token:
                auth.revoke(self.cookie_token())
                self.redirect(token, auth.ttl)
            else:
                self.locked(status, error=True)

        def get(self, head=False):
            if not self.trusted():
                return
            path = urllib.parse.urlsplit(self.path).path
            if path == "/logout":
                auth.revoke(self.cookie_token())
                self.redirect("", 0)
                return
            if not auth.authenticate(self.cookie_token()):
                self.locked(head=head)
                return
            if path not in ("/", "/index.html", "/latest.json", "/latest.md") and not re.fullmatch(r"/[a-f0-9]{12}\.(json|md)", path):
                self.send_error(404)
                return
            target = directory / ("index.html" if path == "/" else path[1:])
            if target.is_symlink() or target.resolve().parent != directory:
                self.send_error(404)
                return
            if head:
                super().do_HEAD()
            else:
                super().do_GET()

        def do_GET(self):
            self.get()

        def do_HEAD(self):
            self.get(head=True)

        def list_directory(self, path):
            self.send_error(404)
            return None

        def end_headers(self):
            self.send_header("X-Watchtower-App", "dashboard-v2")
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            super().end_headers()

    return Handler
