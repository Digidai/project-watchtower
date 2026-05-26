#!/usr/bin/env python3
"""Bounded project health monitoring without third-party dependencies.

The implementation intentionally uses only the Python standard library so it can
run on a minimal Oracle Linux instance without invoking dnf.
"""

from __future__ import annotations

import argparse
import base64
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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable


DEFAULT_USER_AGENT = "DigidaiProjectWatchtower/0.1 (+https://github.com/Digidai/project-watchtower)"
UTC = dt.timezone.utc


@dataclasses.dataclass(frozen=True)
class UrlResult:
    url: str
    source: str
    repo: str | None
    critical: bool
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


@dataclasses.dataclass(frozen=True)
class UrlTarget:
    url: str
    source: str
    repo: str | None = None
    critical: bool = False


@dataclasses.dataclass(frozen=True)
class GitHubRepoCheck:
    repo: str
    kind: str
    ok: bool
    status: str
    detail: str | None = None
    url: str | None = None
    checked_at: str | None = None


class ByteBudget:
    def __init__(self, limit: int) -> None:
        self.limit = max(0, limit)
        self.used = 0
        self._lock = threading.Lock()

    def reserve(self, n: int) -> int:
        with self._lock:
            remaining = max(0, self.limit - self.used)
            take = min(max(0, n), remaining)
            self.used += take
            return take

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self.limit - self.used)


class ApiBudget:
    def __init__(self, limit: int) -> None:
        self.limit = max(0, limit)
        self.used = 0
        self._lock = threading.Lock()

    def spend(self) -> bool:
        with self._lock:
            if self.used >= self.limit:
                return False
            self.used += 1
            return True


def utc_now() -> str:
    return dt.datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def is_blocked_host(hostname: str | None, blocked_hosts: list[str]) -> bool:
    if not hostname:
        return True
    return host_matches(hostname, blocked_hosts)


def is_allowed_target(target: UrlTarget, config: dict[str, Any]) -> bool:
    parsed = urllib.parse.urlparse(target.url)
    allowed_hosts = list(config.get("allowed_hosts", []))
    blocked_hosts = list(config.get("blocked_hosts", []))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    if is_blocked_host(parsed.hostname, blocked_hosts):
        return False
    if host_matches(parsed.hostname, allowed_hosts):
        return True
    if target.source in {"repo_homepage", "readme_link"} and bool(config.get("allow_repo_discovered_hosts", False)):
        return True
    return False


def filter_allowed_targets(targets: Iterable[UrlTarget], config: dict[str, Any]) -> tuple[list[UrlTarget], list[str]]:
    accepted: list[UrlTarget] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for target in targets:
        url = normalize_url(target.url)
        if not url:
            rejected.append(target.url)
            continue
        normalized = dataclasses.replace(target, url=url)
        if not is_allowed_target(normalized, config):
            rejected.append(url)
            continue
        key = url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        accepted.append(normalized)
    return accepted, rejected


def request_json(url: str, token: str | None, timeout: float, max_bytes: int = 20 * 1024 * 1024) -> tuple[Any, dict[str, str]]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": DEFAULT_USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(max_bytes)
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


URL_RE = re.compile(r"https?://[^\s<>'\"\\)\\]]+")


def sorted_recent_repos(repos: list[RepoSummary]) -> list[RepoSummary]:
    return sorted(repos, key=lambda r: r.pushed_at or r.updated_at or "", reverse=True)


def decode_readme_content(payload: dict[str, Any]) -> str:
    content = payload.get("content")
    encoding = payload.get("encoding")
    if not isinstance(content, str) or encoding != "base64":
        return ""
    try:
        return base64.b64decode(content, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return ""


def extract_urls_from_text(text: str, max_links: int) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:")
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if len(urls) >= max_links:
            break
    return urls


def fetch_repo_readme_links(
    owner: str,
    repo: RepoSummary,
    timeout: float,
    token: str | None,
    api_budget: ApiBudget,
    max_links: int,
) -> tuple[list[UrlTarget], GitHubRepoCheck]:
    if not api_budget.spend():
        return [], GitHubRepoCheck(repo=repo.name, kind="readme", ok=False, status="skipped", detail="api budget exhausted")
    url = f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo.name)}/readme"
    try:
        payload, _headers = request_json(url, token, timeout, max_bytes=3 * 1024 * 1024)
        if not isinstance(payload, dict):
            raise RuntimeError("unexpected readme payload")
        text = decode_readme_content(payload)
        links = extract_urls_from_text(text, max_links=max_links)
        targets = [
            UrlTarget(url=link, source="readme_link", repo=repo.name, critical=False)
            for link in links
        ]
        return targets, GitHubRepoCheck(
            repo=repo.name,
            kind="readme",
            ok=True,
            status="ok",
            detail=f"{len(links)} links",
            url=payload.get("html_url"),
            checked_at=utc_now(),
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return [], GitHubRepoCheck(repo=repo.name, kind="readme", ok=False, status="missing", detail="README not found", checked_at=utc_now())
        return [], GitHubRepoCheck(repo=repo.name, kind="readme", ok=False, status="error", detail=f"http {exc.code}", checked_at=utc_now())
    except Exception as exc:
        return [], GitHubRepoCheck(repo=repo.name, kind="readme", ok=False, status="error", detail=type(exc).__name__ + ": " + str(exc)[:160], checked_at=utc_now())


def fetch_repo_workflow_check(
    owner: str,
    repo: RepoSummary,
    timeout: float,
    token: str | None,
    api_budget: ApiBudget,
) -> GitHubRepoCheck:
    if not api_budget.spend():
        return GitHubRepoCheck(repo=repo.name, kind="workflow", ok=False, status="skipped", detail="api budget exhausted")
    url = f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo.name)}/actions/runs?per_page=1"
    try:
        payload, _headers = request_json(url, token, timeout, max_bytes=512 * 1024)
        if not isinstance(payload, dict):
            raise RuntimeError("unexpected workflow payload")
        runs = payload.get("workflow_runs") or []
        if not runs:
            return GitHubRepoCheck(repo=repo.name, kind="workflow", ok=True, status="none", detail="no workflow runs", checked_at=utc_now())
        run = runs[0]
        conclusion = run.get("conclusion")
        status = run.get("status") or "unknown"
        ok = status in {"queued", "in_progress"} or conclusion in {None, "success", "neutral", "skipped"}
        return GitHubRepoCheck(
            repo=repo.name,
            kind="workflow",
            ok=ok,
            status=str(conclusion or status),
            detail=run.get("name"),
            url=run.get("html_url"),
            checked_at=utc_now(),
        )
    except urllib.error.HTTPError as exc:
        if exc.code in {403, 404}:
            return GitHubRepoCheck(repo=repo.name, kind="workflow", ok=True, status="unavailable", detail=f"http {exc.code}", checked_at=utc_now())
        return GitHubRepoCheck(repo=repo.name, kind="workflow", ok=False, status="error", detail=f"http {exc.code}", checked_at=utc_now())
    except Exception as exc:
        return GitHubRepoCheck(repo=repo.name, kind="workflow", ok=False, status="error", detail=type(exc).__name__ + ": " + str(exc)[:160], checked_at=utc_now())


def collect_github_repo_checks(
    owner: str,
    repos: list[RepoSummary],
    mode: str,
    timeout: float,
    policy: dict[str, Any],
) -> tuple[list[GitHubRepoCheck], list[UrlTarget], dict[str, Any]]:
    if mode == "light":
        return [], [], {"api_detail_requests_used": 0, "detail_repo_count": 0}

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("WATCHTOWER_GITHUB_TOKEN")
    detail_limits = policy.get("github_detail_repos", {})
    max_repos = int(detail_limits.get(mode, detail_limits.get("daily", 20)))
    api_request_limits = policy.get("github_detail_api_requests", {})
    default_api_limit = 80 if token else 45
    api_budget = ApiBudget(int(api_request_limits.get(mode, default_api_limit)))
    max_links = int(policy.get("readme_link_max_per_repo", 5))
    candidates = [
        repo for repo in sorted_recent_repos(repos)
        if not repo.archived and not repo.fork
    ][:max_repos]

    checks: list[GitHubRepoCheck] = []
    discovered_targets: list[UrlTarget] = []
    detail_workers = max(1, int(policy.get("github_detail_concurrency", 4)))

    def check_repo(repo: RepoSummary) -> tuple[list[GitHubRepoCheck], list[UrlTarget]]:
        readme_targets, readme_check = fetch_repo_readme_links(owner, repo, timeout, token, api_budget, max_links)
        workflow_check = fetch_repo_workflow_check(owner, repo, timeout, token, api_budget)
        return [readme_check, workflow_check], readme_targets

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(detail_workers, max(1, len(candidates)))) as pool:
        future_map = {pool.submit(check_repo, repo): repo for repo in candidates}
        for future in concurrent.futures.as_completed(future_map):
            repo_checks, repo_targets = future.result()
            checks.extend(repo_checks)
            discovered_targets.extend(repo_targets)

    meta = {
        "api_detail_requests_used": api_budget.used,
        "api_detail_request_limit": api_budget.limit,
        "detail_repo_count": len(candidates),
        "readme_link_max_per_repo": max_links,
    }
    return checks, discovered_targets, meta


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
        expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        return (expiry - dt.datetime.now(UTC)).days
    except Exception:
        return None


def fetch_url(target: UrlTarget, timeout: float, budget: ByteBudget, per_request_limit: int) -> UrlResult:
    url = target.url
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
    if budget.remaining <= 0:
        error = "byte budget exhausted"
    else:
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(resp.status)
                final_url = resp.geturl()
                bytes_read = read_limited(resp, budget, per_request_limit)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            final_url = exc.geturl()
            error = f"http {exc.code}"
        except Exception as exc:
            error = type(exc).__name__ + ": " + str(exc)[:180]

    elapsed_ms = int((time.monotonic() - started) * 1000)
    ok = status is not None and 200 <= status < 400 and error is None
    cert_sources = {"explicit", "repo_homepage"}
    return UrlResult(
        url=url,
        source=target.source,
        repo=target.repo,
        critical=target.critical,
        ok=ok,
        status=status,
        elapsed_ms=elapsed_ms,
        bytes_read=bytes_read,
        final_url=final_url,
        error=error,
        tls_days_remaining=tls_days_remaining(url, min(timeout, 4.0)) if target.source in cert_sources else None,
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


def check_to_dict(check: GitHubRepoCheck) -> dict[str, Any]:
    return dataclasses.asdict(check)


def staleness_days(iso_value: str | None) -> int | None:
    if not iso_value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt.datetime.now(UTC) - parsed).days


def summarize(
    repos: list[RepoSummary],
    url_results: list[UrlResult],
    repo_checks: list[GitHubRepoCheck],
    github_meta: dict[str, Any],
    slow_url_ms: int = 8000,
) -> dict[str, Any]:
    failed_urls = [r for r in url_results if not r.ok]
    failed_critical_urls = [r for r in failed_urls if r.critical]
    failed_observed_urls = [r for r in failed_urls if not r.critical]
    slow_urls = [r for r in url_results if r.ok and r.elapsed_ms > slow_url_ms]
    stale_repos = [r for r in repos if (staleness_days(r.pushed_at) or 0) > 365 and not r.archived]
    cert_warnings = [
        r for r in url_results if r.tls_days_remaining is not None and r.tls_days_remaining < 30
    ]
    failed_repo_checks = [c for c in repo_checks if not c.ok and c.status not in {"missing", "skipped"}]
    status = "ok"
    if failed_critical_urls:
        status = "fail"
    elif failed_observed_urls or slow_urls or cert_warnings or failed_repo_checks or github_meta.get("error"):
        status = "warn"
    return {
        "repo_count": len(repos),
        "archived_repo_count": sum(1 for r in repos if r.archived),
        "fork_count": sum(1 for r in repos if r.fork),
        "url_count": len(url_results),
        "failed_url_count": len(failed_urls),
        "failed_critical_url_count": len(failed_critical_urls),
        "failed_observed_url_count": len(failed_observed_urls),
        "slow_url_count": len(slow_urls),
        "stale_repo_count": len(stale_repos),
        "cert_warning_count": len(cert_warnings),
        "repo_check_count": len(repo_checks),
        "failed_repo_check_count": len(failed_repo_checks),
        "slow_url_ms": slow_url_ms,
        "status": status,
    }


def build_targets(
    config: dict[str, Any],
    repos: list[RepoSummary],
    mode: str,
    discovered_targets: list[UrlTarget],
) -> tuple[list[UrlTarget], list[str]]:
    explicit = [
        UrlTarget(url=url, source="explicit", repo=None, critical=True)
        for url in list(config.get("urls", []))
    ]
    repo_targets: list[UrlTarget] = []
    for repo in repos:
        if repo.url:
            repo_targets.append(UrlTarget(url=repo.url, source="github_repo", repo=repo.name, critical=False))
        if repo.homepage:
            repo_targets.append(UrlTarget(url=repo.homepage, source="repo_homepage", repo=repo.name, critical=False))
    if mode == "light":
        targets = explicit
    else:
        targets = explicit + repo_targets + discovered_targets
    return filter_allowed_targets(targets, config)


def cleanup_old_reports(output_dir: Path, keep: int) -> None:
    if keep <= 0:
        return
    json_archives = sorted(
        [p for p in output_dir.glob("*.json") if p.name != "latest.json"],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    stale_json = json_archives[keep:]
    for json_path in stale_json:
        with contextlib.suppress(Exception):
            json_path.unlink()
        md_path = json_path.with_suffix(".md")
        with contextlib.suppress(Exception):
            md_path.unlink()


def write_reports(output_dir: Path, report: dict[str, Any], keep: int = 2000) -> None:
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
    cleanup_old_reports(output_dir, keep=keep)


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
        f"- Critical URL failures: `{summary.get('failed_critical_url_count', 0)}`",
        f"- Repository checks: `{summary.get('repo_check_count', 0)}`",
        f"- Slow URLs: `{summary['slow_url_count']}`",
        f"- Certificate warnings: `{summary['cert_warning_count']}`",
        "",
        "## Critical URL Failures",
        "",
    ]
    critical_failed = [r for r in report["urls"] if not r["ok"] and r.get("critical")]
    if critical_failed:
        for item in critical_failed[:50]:
            lines.append(f"- `{item['status']}` {item['url']} - {item.get('error') or 'failed'}")
    else:
        lines.append("- None")
    lines += ["", "## Observed URL Failures", ""]
    observed_failed = [r for r in report["urls"] if not r["ok"] and not r.get("critical")]
    if observed_failed:
        for item in observed_failed[:50]:
            repo = f" `{item.get('repo')}`" if item.get("repo") else ""
            lines.append(f"- `{item['status']}`{repo} {item['url']} - {item.get('error') or 'failed'}")
    else:
        lines.append("- None")
    lines += ["", "## Slow URLs", ""]
    slow_threshold = int(summary.get("slow_url_ms", 8000))
    slow = [r for r in report["urls"] if r["ok"] and r["elapsed_ms"] > slow_threshold]
    if slow:
        for item in slow[:50]:
            lines.append(f"- `{item['elapsed_ms']}ms` {item['url']}")
    else:
        lines.append("- None")
    lines += ["", "## Recently Updated Repositories", ""]
    repos = sorted(report["repositories"], key=lambda r: r.get("pushed_at") or "", reverse=True)
    for repo in repos[:20]:
        lines.append(f"- `{repo['name']}` pushed `{repo.get('pushed_at')}` stars `{repo['stars']}`")
    lines += ["", "## GitHub Repo Checks", ""]
    checks = report.get("github_repo_checks", [])
    if checks:
        for check in checks[:40]:
            mark = "ok" if check.get("ok") else "warn"
            lines.append(f"- `{mark}` `{check.get('repo')}` `{check.get('kind')}` `{check.get('status')}` {check.get('detail') or ''}".rstrip())
    else:
        lines.append("- None")
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

    try:
        repos, github_meta = fetch_repositories(owner, timeout=timeout, max_pages=int(policy.get("github_max_pages", 5)))
    except Exception as exc:
        repos = []
        github_meta = {
            "pages": 0,
            "authenticated": bool(os.environ.get("GITHUB_TOKEN") or os.environ.get("WATCHTOWER_GITHUB_TOKEN")),
            "error": type(exc).__name__ + ": " + str(exc)[:180],
        }

    repo_checks, discovered_targets, github_detail_meta = collect_github_repo_checks(owner, repos, args.mode, timeout, policy)
    github_meta.update(github_detail_meta)
    targets, rejected_urls = build_targets(config, repos, args.mode, discovered_targets)
    mode_max_urls = policy.get("mode_max_urls", {})
    configured_max_urls = mode_max_urls.get(args.mode)
    if configured_max_urls is not None:
        targets = targets[: int(configured_max_urls)]
    if args.max_urls is not None:
        targets = targets[: args.max_urls]

    budget = ByteBudget(max_bytes)
    results: list[UrlResult] = []
    if targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            future_map = {
                pool.submit(fetch_url, target, timeout, budget, per_request_limit): target
                for target in targets
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
        "summary": summarize(repos, results, repo_checks, github_meta, slow_url_ms=int(policy.get("slow_url_ms", 8000))),
        "repositories": [repo_to_dict(r) for r in sorted(repos, key=lambda r: r.name.lower())],
        "urls": [result_to_dict(r) for r in results],
        "github_repo_checks": [check_to_dict(c) for c in repo_checks],
        "discovered_url_count": len(discovered_targets),
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
    write_reports(output_dir, report, keep=int(policy.get("report_retention", 2000)))
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
