#!/usr/bin/env python3
"""Bounded project health monitoring without third-party dependencies.

The implementation intentionally uses only the Python standard library so it can
run on a minimal Oracle Linux instance without invoking dnf.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable


DEFAULT_USER_AGENT = "DigidaiProjectWatchtower/0.1 (+https://github.com/Digidai/project-watchtower)"


@dataclasses.dataclass(frozen=True)
class UrlResult:
    url: str
    ok: bool
    status: int | None
    elapsed_ms: int
    bytes_read: int
    final_url: str | None = None
    error: str | None = None
    tls_days_remaining: int | None = None


@dataclasses.dataclass(frozen=True)
class RepoSummary:
    name: str
    url: str
    homepage: str | None
    archived: bool
    fork: bool
    default_branch: str | None
    pushed_at: str | None
    updated_at: str | None
    stars: int
    open_issues: int
    language: str | None


class ByteBudget:
    def __init__(self, limit: int) -> None:
        self.limit = max(0, limit)
        self.used = 0

    def reserve(self, n: int) -> int:
        remaining = max(0, self.limit - self.used)
        take = min(max(0, n), remaining)
        self.used += take
        return take

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def normalize_url(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    parsed = urllib.parse.urlparse(value)
    if not parsed.scheme:
        value = "https://" + value
        parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def host_matches(hostname: str, allowed: Iterable[str]) -> bool:
    host = hostname.lower().rstrip(".")
    for pattern in allowed:
        p = pattern.lower().rstrip(".")
        if p.startswith("*."):
            suffix = p[1:]
            if host.endswith(suffix) and host != p[2:]:
                return True
        elif host == p:
            return True
    return False


def filter_allowed_urls(urls: Iterable[str], allowed_hosts: list[str]) -> tuple[list[str], list[str]]:
    accepted: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for raw in urls:
        url = normalize_url(raw)
        if not url:
            rejected.append(raw)
            continue
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname or not host_matches(parsed.hostname, allowed_hosts):
            rejected.append(url)
            continue
        key = url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        accepted.append(url)
    return accepted, rejected


def request_json(url: str, token: str | None, timeout: float) -> tuple[Any, dict[str, str]]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": DEFAULT_USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(20 * 1024 * 1024)
        headers_out = {k.lower(): v for k, v in resp.headers.items()}
        return json.loads(body.decode("utf-8")), headers_out


def next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        bits = part.strip().split(";")
        if len(bits) < 2:
            continue
        url_part = bits[0].strip()
        rels = [b.strip() for b in bits[1:]]
        if 'rel="next"' in rels and url_part.startswith("<") and url_part.endswith(">"):
            return url_part[1:-1]
    return None


def fetch_repositories(owner: str, timeout: float, max_pages: int) -> tuple[list[RepoSummary], dict[str, Any]]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("WATCHTOWER_GITHUB_TOKEN")
    url = f"https://api.github.com/users/{urllib.parse.quote(owner)}/repos?per_page=100&sort=updated&type=owner"
    repos: list[RepoSummary] = []
    pages = 0
    rate_headers: dict[str, str] = {}
    while url and pages < max_pages:
        pages += 1
        payload, headers = request_json(url, token, timeout)
        rate_headers = headers
        if not isinstance(payload, list):
            raise RuntimeError(f"Unexpected GitHub API payload for {url}")
        for item in payload:
            repos.append(
                RepoSummary(
                    name=str(item.get("name") or ""),
                    url=str(item.get("html_url") or ""),
                    homepage=normalize_url(item.get("homepage")),
                    archived=bool(item.get("archived")),
                    fork=bool(item.get("fork")),
                    default_branch=item.get("default_branch"),
                    pushed_at=item.get("pushed_at"),
                    updated_at=item.get("updated_at"),
                    stars=int(item.get("stargazers_count") or 0),
                    open_issues=int(item.get("open_issues_count") or 0),
                    language=item.get("language"),
                )
            )
        url = next_link(headers.get("link"))
    metadata = {
        "pages": pages,
        "rate_limit_remaining": rate_headers.get("x-ratelimit-remaining"),
        "rate_limit_reset": rate_headers.get("x-ratelimit-reset"),
        "authenticated": bool(token),
    }
    return repos, metadata


def read_limited(resp: Any, budget: ByteBudget, per_request_limit: int) -> int:
    total = 0
    chunk_size = 32 * 1024
    while total < per_request_limit and budget.remaining > 0:
        want = min(chunk_size, per_request_limit - total, budget.remaining)
        if want <= 0:
            break
        data = resp.read(want)
        if not data:
            break
        budget.reserve(len(data))
        total += len(data)
    return total


def tls_days_remaining(url: str, timeout: float) -> int | None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not not_after:
            return None
        expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.UTC)
        return (expiry - dt.datetime.now(dt.UTC)).days
    except Exception:
        return None


def fetch_url(url: str, timeout: float, budget: ByteBudget, per_request_limit: int) -> UrlResult:
    started = time.monotonic()
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/json,text/plain,*/*;q=0.2",
    }
    status: int | None = None
    final_url: str | None = None
    bytes_read = 0
    error: str | None = None

    # GET is deliberate: a HEAD-only check can pass while the real page body is
    # broken. The body read is still capped by the per-request and per-run budget.
    for method in ("GET", "HEAD"):
        if method == "GET" and budget.remaining <= 0:
            error = "byte budget exhausted"
            break
        try:
            req = urllib.request.Request(url, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(resp.status)
                final_url = resp.geturl()
                if method == "GET":
                    bytes_read = read_limited(resp, budget, per_request_limit)
                break
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            final_url = exc.geturl()
            if method == "GET" and exc.code in {403, 405, 429, 500, 501}:
                continue
            error = f"http {exc.code}"
            break
        except Exception as exc:
            if method == "GET":
                continue
            error = type(exc).__name__ + ": " + str(exc)[:180]
            break

    elapsed_ms = int((time.monotonic() - started) * 1000)
    ok = status is not None and 200 <= status < 400 and error is None
    return UrlResult(
        url=url,
        ok=ok,
        status=status,
        elapsed_ms=elapsed_ms,
        bytes_read=bytes_read,
        final_url=final_url,
        error=error,
        tls_days_remaining=tls_days_remaining(url, min(timeout, 5.0)),
    )


def collect_system_metrics() -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "timestamp": utc_now(),
        "hostname": socket.gethostname(),
        "loadavg": os.getloadavg() if hasattr(os, "getloadavg") else None,
        "disk_root": shutil.disk_usage("/")._asdict(),
    }
    with contextlib.suppress(Exception):
        meminfo: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            meminfo[key] = int(value.strip().split()[0]) * 1024
        metrics["meminfo"] = {
            "MemTotal": meminfo.get("MemTotal"),
            "MemAvailable": meminfo.get("MemAvailable"),
            "SwapTotal": meminfo.get("SwapTotal"),
            "SwapFree": meminfo.get("SwapFree"),
        }
    with contextlib.suppress(Exception):
        interfaces: dict[str, dict[str, int]] = {}
        for line in Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]:
            name, data = line.split(":", 1)
            fields = data.split()
            interfaces[name.strip()] = {
                "rx_bytes": int(fields[0]),
                "rx_packets": int(fields[1]),
                "tx_bytes": int(fields[8]),
                "tx_packets": int(fields[9]),
            }
        metrics["network_interfaces"] = interfaces
    return metrics


def repo_to_dict(repo: RepoSummary) -> dict[str, Any]:
    return dataclasses.asdict(repo)


def result_to_dict(result: UrlResult) -> dict[str, Any]:
    return dataclasses.asdict(result)


def staleness_days(iso_value: str | None) -> int | None:
    if not iso_value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt.datetime.now(dt.UTC) - parsed).days


def summarize(repos: list[RepoSummary], url_results: list[UrlResult]) -> dict[str, Any]:
    failed_urls = [r for r in url_results if not r.ok]
    slow_urls = [r for r in url_results if r.ok and r.elapsed_ms > 3000]
    stale_repos = [r for r in repos if (staleness_days(r.pushed_at) or 0) > 365 and not r.archived]
    cert_warnings = [
        r for r in url_results if r.tls_days_remaining is not None and r.tls_days_remaining < 30
    ]
    return {
        "repo_count": len(repos),
        "archived_repo_count": sum(1 for r in repos if r.archived),
        "fork_count": sum(1 for r in repos if r.fork),
        "url_count": len(url_results),
        "failed_url_count": len(failed_urls),
        "slow_url_count": len(slow_urls),
        "stale_repo_count": len(stale_repos),
        "cert_warning_count": len(cert_warnings),
        "status": "fail" if failed_urls else "warn" if slow_urls or cert_warnings else "ok",
    }


def build_urls(config: dict[str, Any], repos: list[RepoSummary], mode: str) -> tuple[list[str], list[str]]:
    explicit = list(config.get("urls", []))
    repo_urls: list[str] = []
    for repo in repos:
        if repo.url:
            repo_urls.append(repo.url)
        if repo.homepage:
            repo_urls.append(repo.homepage)
    if mode == "light":
        urls = explicit
    else:
        urls = explicit + repo_urls
    return filter_allowed_urls(urls, list(config.get("allowed_hosts", [])))


def write_reports(output_dir: Path, report: dict[str, Any]) -> None:
    ensure_dir(output_dir)
    latest_json = output_dir / "latest.json"
    latest_md = output_dir / "latest.md"
    run_id = report["run"]["id"]
    archive_json = output_dir / f"{run_id}.json"
    archive_md = output_dir / f"{run_id}.md"
    json_text = json.dumps(report, indent=2, sort_keys=True)
    md_text = render_markdown(report)
    latest_json.write_text(json_text + "\n", encoding="utf-8")
    latest_md.write_text(md_text, encoding="utf-8")
    archive_json.write_text(json_text + "\n", encoding="utf-8")
    archive_md.write_text(md_text, encoding="utf-8")


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        f"# Project Watchtower Report",
        "",
        f"- Run: `{report['run']['id']}`",
        f"- Mode: `{report['run']['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- Generated: `{report['run']['started_at']}`",
        f"- Repositories: `{summary['repo_count']}`",
        f"- URLs checked: `{summary['url_count']}`",
        f"- Failed URLs: `{summary['failed_url_count']}`",
        f"- Slow URLs: `{summary['slow_url_count']}`",
        f"- Certificate warnings: `{summary['cert_warning_count']}`",
        "",
        "## Failed URLs",
        "",
    ]
    failed = [r for r in report["urls"] if not r["ok"]]
    if failed:
        for item in failed[:50]:
            lines.append(f"- `{item['status']}` {item['url']} - {item.get('error') or 'failed'}")
    else:
        lines.append("- None")
    lines += ["", "## Slow URLs", ""]
    slow = [r for r in report["urls"] if r["ok"] and r["elapsed_ms"] > 3000]
    if slow:
        for item in slow[:50]:
            lines.append(f"- `{item['elapsed_ms']}ms` {item['url']}")
    else:
        lines.append("- None")
    lines += ["", "## Recently Updated Repositories", ""]
    repos = sorted(report["repositories"], key=lambda r: r.get("pushed_at") or "", reverse=True)
    for repo in repos[:20]:
        lines.append(f"- `{repo['name']}` pushed `{repo.get('pushed_at')}` stars `{repo['stars']}`")
    lines.append("")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    policy = config.get("policy", {})
    timeout = float(policy.get("timeout_seconds", 10))
    workers = int(policy.get("max_concurrency", 3))
    per_request_limit = int(policy.get("per_request_max_bytes", 2 * 1024 * 1024))
    mode_budget_mb = policy.get("mode_max_megabytes", {})
    max_bytes = int(float(mode_budget_mb.get(args.mode, mode_budget_mb.get("daily", 32))) * 1024 * 1024)
    if args.max_bytes is not None:
        max_bytes = args.max_bytes
    owner = str(config.get("github_owner", "Digidai"))

    started_at = utc_now()
    run_id_seed = f"{started_at}:{args.mode}:{owner}".encode("utf-8")
    run_id = hashlib.sha256(run_id_seed).hexdigest()[:12]

    repos, github_meta = fetch_repositories(owner, timeout=timeout, max_pages=int(policy.get("github_max_pages", 5)))
    urls, rejected_urls = build_urls(config, repos, args.mode)
    if args.max_urls is not None:
        urls = urls[: args.max_urls]

    budget = ByteBudget(max_bytes)
    results: list[UrlResult] = []
    if urls:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            future_map = {
                pool.submit(fetch_url, url, timeout, budget, per_request_limit): url
                for url in urls
            }
            for future in concurrent.futures.as_completed(future_map):
                results.append(future.result())
    results.sort(key=lambda r: r.url)

    report = {
        "run": {
            "id": run_id,
            "mode": args.mode,
            "started_at": started_at,
            "completed_at": utc_now(),
            "config": str(Path(args.config).resolve()),
        },
        "github": github_meta,
        "summary": summarize(repos, results),
        "repositories": [repo_to_dict(r) for r in sorted(repos, key=lambda r: r.name.lower())],
        "urls": [result_to_dict(r) for r in results],
        "rejected_urls": rejected_urls,
        "resource_budget": {
            "max_bytes": max_bytes,
            "bytes_read": budget.used,
            "per_request_max_bytes": per_request_limit,
            "max_concurrency": workers,
        },
        "system": collect_system_metrics(),
    }

    output_dir = Path(args.output_dir)
    write_reports(output_dir, report)
    print(json.dumps({"summary": report["summary"], "output_dir": str(output_dir), "run_id": run_id}, sort_keys=True))
    return 0 if report["summary"]["status"] != "fail" or args.no_fail else 2


def serve(args: argparse.Namespace) -> int:
    import http.server

    directory = str(Path(args.output_dir).resolve())
    os.chdir(directory)
    handler = http.server.SimpleHTTPRequestHandler
    server = http.server.ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Serving {directory} on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="project-watchtower")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run a bounded health check")
    run_p.add_argument("--mode", choices=["light", "daily", "weekly"], default="light")
    run_p.add_argument("--config", default="config/targets.json")
    run_p.add_argument("--output-dir", default="reports")
    run_p.add_argument("--max-urls", type=int)
    run_p.add_argument("--max-bytes", type=int)
    run_p.add_argument("--no-fail", action="store_true", help="always exit 0 after writing a report")
    run_p.set_defaults(func=run)

    serve_p = sub.add_parser("serve", help="serve generated reports over local HTTP")
    serve_p.add_argument("--output-dir", default="reports")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8765)
    serve_p.set_defaults(func=serve)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
