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
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable


DEFAULT_USER_AGENT = "DigidaiProjectWatchtower/0.1 (+https://github.com/Digidai/project-watchtower)"
UTC = dt.timezone.utc
RUN_MODES = (
    "core",
    "self",
    "github-lite",
    "daily",
    "weekly",
    "venture-check",
    "venture-discover",
)


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
class VentureDexStartup:
    name: str
    profile_url: str
    company_url: str | None
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class GitHubRepoCheck:
    repo: str
    kind: str
    ok: bool
    status: str
    detail: str | None = None
    url: str | None = None
    checked_at: str | None = None


@dataclasses.dataclass(frozen=True)
class SelfCheck:
    name: str
    ok: bool
    status: str
    detail: str | None = None


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


def is_public_hostname(hostname: str | None) -> bool:
    if not hostname:
        return False
    host = hostname.lower().rstrip(".")
    if host in {"localhost"} or host.endswith(".localhost") or host.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        return True


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme not in {"http", "https"} or not is_public_hostname(parsed.hostname):
            raise urllib.error.HTTPError(newurl, code, "redirect to non-public host blocked", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


SAFE_OPENER = urllib.request.build_opener(SafeRedirectHandler)


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
    if target.source == "venturedex_company" and bool(config.get("allow_venturedex_discovered_hosts", False)):
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
    if mode in {"core", "self", "venture-check", "venture-discover"}:
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


def request_text(url: str, timeout: float, max_bytes: int, accept: str = "text/html,*/*;q=0.2") -> tuple[str, int, str]:
    normalized = normalize_url(url)
    if not normalized:
        raise ValueError(f"invalid url: {url}")
    parsed = urllib.parse.urlparse(normalized)
    if not is_public_hostname(parsed.hostname):
        raise ValueError(f"non-public host blocked: {parsed.hostname}")
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": accept,
    }
    req = urllib.request.Request(normalized, headers=headers, method="GET")
    with SAFE_OPENER.open(req, timeout=timeout) as resp:
        body = resp.read(max_bytes)
        charset = resp.headers.get_content_charset() or "utf-8"
        return body.decode(charset, errors="replace"), len(body), resp.geturl()


def iter_jsonld_nodes(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, list):
        for item in value:
            yield from iter_jsonld_nodes(item)
        return
    if not isinstance(value, dict):
        return
    graph = value.get("@graph")
    if isinstance(graph, list):
        for item in graph:
            yield from iter_jsonld_nodes(item)
    yield value


LD_JSON_RE = re.compile(
    r"<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
STARTUP_HREF_RE = re.compile(r"href=[\"']([^\"']*/startups/[^\"']*)[\"']", re.IGNORECASE)


def extract_jsonld_payloads(html: str) -> list[Any]:
    payloads: list[Any] = []
    for match in LD_JSON_RE.finditer(html):
        text = match.group(1).strip()
        if not text:
            continue
        with contextlib.suppress(json.JSONDecodeError):
            payloads.append(json.loads(text))
    return payloads


def extract_venturedex_profiles(html: str, source_url: str) -> list[str]:
    base = source_url.rstrip("/") + "/"
    profiles: list[str] = []
    seen: set[str] = set()

    def add(value: str | None) -> None:
        if not value:
            return
        url = normalize_url(urllib.parse.urljoin(base, value))
        if not url:
            return
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc.lower().rstrip(".") != urllib.parse.urlparse(source_url).netloc.lower().rstrip("."):
            return
        if not parsed.path.startswith("/startups/"):
            return
        key = url.rstrip("/")
        if key in seen:
            return
        seen.add(key)
        profiles.append(key)

    for payload in extract_jsonld_payloads(html):
        for node in iter_jsonld_nodes(payload):
            items = node.get("itemListElement")
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict):
                    add(item.get("url"))

    for match in STARTUP_HREF_RE.finditer(html):
        add(match.group(1))
    return profiles


def extract_venturedex_profiles_from_sitemap(xml_text: str) -> list[str]:
    profiles: list[str] = []
    seen: set[str] = set()
    root = ET.fromstring(xml_text)
    for elem in root.iter():
        if not elem.tag.endswith("loc") or not elem.text:
            continue
        url = normalize_url(elem.text)
        if not url:
            continue
        parsed = urllib.parse.urlparse(url)
        if not parsed.path.startswith("/startups/"):
            continue
        key = url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        profiles.append(key)
    return profiles


def company_url_from_profile(profile_url: str, html: str, source_host: str) -> VentureDexStartup:
    profile_name = urllib.parse.urlparse(profile_url).path.rstrip("/").rsplit("/", 1)[-1]
    name = profile_name
    for payload in extract_jsonld_payloads(html):
        for node in iter_jsonld_nodes(payload):
            node_type = node.get("@type")
            if isinstance(node_type, list):
                is_org = "Organization" in node_type
            else:
                is_org = node_type == "Organization"
            if not is_org:
                continue
            url = normalize_url(node.get("url"))
            parsed = urllib.parse.urlparse(url or "")
            if not url or parsed.hostname == source_host:
                continue
            return VentureDexStartup(
                name=str(node.get("name") or name),
                profile_url=profile_url,
                company_url=url,
            )
    return VentureDexStartup(name=name, profile_url=profile_url, company_url=None, error="company url not found")


def collect_venturedex_targets(
    config: dict[str, Any],
    timeout: float,
) -> tuple[list[UrlTarget], list[str], list[VentureDexStartup], dict[str, Any]]:
    venture_config = config.get("venturedex", {})
    source_url = normalize_url(str(venture_config.get("source_url") or "https://venturedex.co/")) or "https://venturedex.co/"
    source_host = urllib.parse.urlparse(source_url).hostname or "venturedex.co"
    source_root = f"{urllib.parse.urlparse(source_url).scheme}://{urllib.parse.urlparse(source_url).netloc}/"
    sitemap_url = urllib.parse.urljoin(source_root, "sitemap.xml")
    max_profiles = int(venture_config.get("profile_max", 80))
    max_companies = int(venture_config.get("company_max", 50))
    profile_concurrency = max(1, int(venture_config.get("profile_concurrency", 6)))
    discovery_page_bytes = int(venture_config.get("profile_page_max_bytes", 768 * 1024))

    discovery_bytes = 0
    discovery_errors: list[str] = []
    profiles: list[str] = []
    try:
        sitemap_text, byte_count, _final_url = request_text(
            sitemap_url,
            timeout=timeout,
            max_bytes=int(venture_config.get("sitemap_max_bytes", 1024 * 1024)),
            accept="application/xml,text/xml,*/*;q=0.2",
        )
        discovery_bytes += byte_count
        profiles = extract_venturedex_profiles_from_sitemap(sitemap_text)
    except Exception as exc:
        discovery_errors.append(f"sitemap: {type(exc).__name__}: {str(exc)[:160]}")

    if not profiles:
        try:
            homepage_text, byte_count, _final_url = request_text(
                source_root,
                timeout=timeout,
                max_bytes=int(venture_config.get("homepage_max_bytes", 2 * 1024 * 1024)),
            )
            discovery_bytes += byte_count
            profiles = extract_venturedex_profiles(homepage_text, source_root)
        except Exception as exc:
            discovery_errors.append(f"homepage: {type(exc).__name__}: {str(exc)[:160]}")

    profiles = profiles[:max_profiles]
    startups: list[VentureDexStartup] = []
    if profiles:
        def fetch_profile(profile_url: str) -> VentureDexStartup:
            try:
                html, byte_count, final_url = request_text(
                    profile_url,
                    timeout=timeout,
                    max_bytes=discovery_page_bytes,
                )
                nonlocal_discovery_bytes.reserve(byte_count)
                return company_url_from_profile(final_url.rstrip("/"), html, source_host)
            except Exception as exc:
                return VentureDexStartup(
                    name=urllib.parse.urlparse(profile_url).path.rstrip("/").rsplit("/", 1)[-1],
                    profile_url=profile_url,
                    company_url=None,
                    error=type(exc).__name__ + ": " + str(exc)[:160],
                )

        class CounterBudget:
            def __init__(self) -> None:
                self.used = 0
                self._lock = threading.Lock()

            def reserve(self, value: int) -> None:
                with self._lock:
                    self.used += max(0, value)

        nonlocal_discovery_bytes = CounterBudget()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(profile_concurrency, len(profiles))) as pool:
            future_map = {pool.submit(fetch_profile, profile_url): profile_url for profile_url in profiles}
            for future in concurrent.futures.as_completed(future_map):
                startups.append(future.result())
        discovery_bytes += nonlocal_discovery_bytes.used

    profile_order = {url: index for index, url in enumerate(profiles)}
    startups.sort(key=lambda item: profile_order.get(item.profile_url, len(profile_order)))
    company_targets: list[UrlTarget] = []
    seen_companies: set[str] = set()
    for startup in startups:
        if not startup.company_url:
            continue
        key = startup.company_url.rstrip("/")
        if key in seen_companies:
            continue
        seen_companies.add(key)
        company_targets.append(
            UrlTarget(url=startup.company_url, source="venturedex_company", repo=startup.name, critical=False)
        )
        if len(company_targets) >= max_companies:
            break

    source_targets = [
        UrlTarget(url=source_root, source="venturedex_source", repo=None, critical=True),
        UrlTarget(url=sitemap_url, source="venturedex_source", repo=None, critical=False),
    ]
    targets, rejected = filter_allowed_targets(source_targets + company_targets, config)
    meta = {
        "source_url": source_root,
        "sitemap_url": sitemap_url,
        "profile_count": len(profiles),
        "profile_pages_checked": len(startups),
        "company_url_count": len([s for s in startups if s.company_url]),
        "company_target_count": len(company_targets),
        "discovery_bytes_read": discovery_bytes,
        "discovery_errors": discovery_errors,
        "profile_max": max_profiles,
        "company_max": max_companies,
    }
    return targets, rejected, startups, meta


def venture_cache_path(state_dir: Path) -> Path:
    return state_dir / "venturedex-cache.json"


def write_venture_cache(state_dir: Path, startups: list[VentureDexStartup], meta: dict[str, Any]) -> None:
    ensure_dir(state_dir)
    existing = read_venture_cache(state_dir)
    payload = {
        "updated_at": utc_now(),
        "cursor": int(existing.get("cursor", 0) or 0),
        "venturedex": meta,
        "startups": [startup_to_dict(startup) for startup in startups],
    }
    atomic_write_text(venture_cache_path(state_dir), json.dumps(payload, indent=2, sort_keys=True) + "\n")


def read_venture_cache(state_dir: Path) -> dict[str, Any]:
    path = venture_cache_path(state_dir)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def cache_age_seconds(cache: dict[str, Any]) -> int | None:
    value = cache.get("updated_at")
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, int((dt.datetime.now(UTC) - parsed).total_seconds()))


def collect_venture_cached_targets(
    config: dict[str, Any],
    timeout: float,
    state_dir: Path,
) -> tuple[list[UrlTarget], list[str], list[VentureDexStartup], dict[str, Any]]:
    venture_config = config.get("venturedex", {})
    batch_size = max(1, int(venture_config.get("check_batch_size", 24)))
    max_age = max(60, int(venture_config.get("cache_max_age_seconds", 6 * 60 * 60)))
    cache = read_venture_cache(state_dir)
    age = cache_age_seconds(cache)
    refreshed = False
    errors: list[str] = []

    if age is None or age > max_age:
        targets, rejected, startups, meta = collect_venturedex_targets(config, timeout)
        write_venture_cache(state_dir, startups, meta)
        cache = read_venture_cache(state_dir)
        age = cache_age_seconds(cache)
        refreshed = True
        if rejected:
            errors.extend(f"rejected during refresh: {url}" for url in rejected[:10])
    startups_payload = cache.get("startups") if isinstance(cache.get("startups"), list) else []

    startups: list[VentureDexStartup] = []
    company_targets: list[UrlTarget] = []
    seen: set[str] = set()
    for item in startups_payload:
        if not isinstance(item, dict):
            continue
        startup = VentureDexStartup(
            name=str(item.get("name") or ""),
            profile_url=str(item.get("profile_url") or ""),
            company_url=normalize_url(item.get("company_url")),
            error=item.get("error") if isinstance(item.get("error"), str) else None,
        )
        startups.append(startup)
        if not startup.company_url:
            continue
        key = startup.company_url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        company_targets.append(UrlTarget(url=startup.company_url, source="venturedex_company", repo=startup.name, critical=False))

    cursor = int(cache.get("cursor", 0) or 0)
    if company_targets:
        start = cursor % len(company_targets)
        ordered = company_targets[start:] + company_targets[:start]
        selected = ordered[: min(batch_size, len(ordered))]
        cache["cursor"] = (start + len(selected)) % len(company_targets)
        cache["last_checked_at"] = utc_now()
        atomic_write_text(venture_cache_path(state_dir), json.dumps(cache, indent=2, sort_keys=True) + "\n")
    else:
        selected = []
        errors.append("no cached company targets")

    source_url = normalize_url(str(venture_config.get("source_url") or "https://venturedex.co/")) or "https://venturedex.co/"
    source_root = f"{urllib.parse.urlparse(source_url).scheme}://{urllib.parse.urlparse(source_url).netloc}/"
    source_targets = [
        UrlTarget(url=source_root, source="venturedex_source", repo=None, critical=True),
    ]
    targets, rejected = filter_allowed_targets(source_targets + selected, config)
    meta = {
        "source_url": source_root,
        "cache_path": str(venture_cache_path(state_dir)),
        "cache_age_seconds": age,
        "cache_refreshed": refreshed,
        "cached_company_target_count": len(company_targets),
        "company_target_count": len(selected),
        "company_url_count": len(company_targets),
        "profile_count": len(startups),
        "profile_pages_checked": 0,
        "discovery_bytes_read": 0,
        "discovery_errors": errors,
        "check_batch_size": batch_size,
    }
    return targets, rejected, startups, meta


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
            parsed = urllib.parse.urlparse(url)
            if not is_public_hostname(parsed.hostname):
                raise ValueError(f"non-public host blocked: {parsed.hostname}")
            req = urllib.request.Request(url, headers=headers, method="GET")
            with SAFE_OPENER.open(req, timeout=timeout) as resp:
                status = int(resp.status)
                final_url = resp.geturl()
                bytes_read = read_limited(resp, budget, per_request_limit)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            final_url = exc.geturl()
            if 300 <= status < 400:
                location = exc.headers.get("Location")
                if location:
                    final_url = urllib.parse.urljoin(url, location)
                bytes_read = read_limited(exc, budget, per_request_limit)
            else:
                error = f"http {exc.code}"
        except Exception as exc:
            error = type(exc).__name__ + ": " + str(exc)[:180]

    elapsed_ms = int((time.monotonic() - started) * 1000)
    ok = status is not None and 200 <= status < 400 and error is None
    cert_sources = {"explicit", "repo_homepage", "venturedex_company", "venturedex_source"}
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
        "cpu_count": os.cpu_count() or 1,
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


def systemctl_is_active(unit: str) -> str:
    try:
        completed = subprocess.run(
            ["systemctl", "is-active", unit],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except Exception as exc:
        return f"error:{type(exc).__name__}"
    return completed.stdout.strip() or f"exit:{completed.returncode}"


def command_stdout(args: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
    except Exception as exc:
        return 127, f"error:{type(exc).__name__}"
    return completed.returncode, completed.stdout.strip()


def parse_ss_listeners(text: str) -> list[dict[str, str]]:
    listeners: list[dict[str, str]] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        proto = fields[0].lower()
        if proto not in {"tcp", "udp"}:
            continue
        local = fields[4]
        address, sep, port = local.rpartition(":")
        if not sep:
            continue
        listeners.append({
            "protocol": proto,
            "address": address or "*",
            "port": port,
            "local": local,
        })
    return listeners


def listener_matches(listener: dict[str, str], protocol: str, listen: str, port: int) -> bool:
    if listener.get("protocol") != protocol.lower():
        return False
    if listener.get("port") != str(port):
        return False
    if listen == "*":
        return True
    return listener.get("address") == listen


def collect_listener_checks(policy: dict[str, Any]) -> list[SelfCheck]:
    expected = policy.get("self_expected_listeners", [])
    if not isinstance(expected, list) or not expected:
        return []
    code, stdout = command_stdout(["ss", "-H", "-lunt"], timeout=8)
    if code != 0:
        return [SelfCheck(
            name="proxy_listener:ss",
            ok=False,
            status="fail",
            detail=stdout or f"ss exit {code}",
        )]
    listeners = parse_ss_listeners(stdout)
    checks: list[SelfCheck] = []
    for item in expected:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "listener")
        protocol = str(item.get("protocol") or "").lower()
        listen = str(item.get("listen") or "*")
        port = int(item.get("port") or 0)
        matches = [listener for listener in listeners if listener_matches(listener, protocol, listen, port)]
        checks.append(SelfCheck(
            name=f"proxy_listener:{name}",
            ok=bool(matches),
            status="ok" if matches else "fail",
            detail=matches[0]["local"] if matches else f"missing {protocol} {listen}:{port}",
        ))
    return checks


def collect_xray_config_check(policy: dict[str, Any]) -> list[SelfCheck]:
    cfg = policy.get("self_xray_config")
    if not isinstance(cfg, dict):
        return []
    path = Path(str(cfg.get("path") or ""))
    name = "proxy_xray_config"
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except Exception as exc:
        return [SelfCheck(name=name, ok=False, status="fail", detail=f"{path}: {type(exc).__name__}")]

    actual_tags = [str(outbound.get("tag") or "") for outbound in data.get("outbounds", []) if isinstance(outbound, dict)]
    expected_tags = [str(tag) for tag in cfg.get("expected_outbound_tags", [])]
    forbidden_terms = [str(term) for term in cfg.get("forbidden_terms", [])]
    forbidden_present = [term for term in forbidden_terms if term in text]

    exclusive_tag = str(cfg.get("exclusive_tag") or "")
    expected_server = str(cfg.get("expected_server") or "")
    expected_servers = [str(server) for server in cfg.get("expected_servers", []) if str(server)]
    if expected_server:
        expected_servers.append(expected_server)
    expected_port = int(cfg.get("expected_port") or 0)
    actual_server = ""
    actual_port = 0
    for outbound in data.get("outbounds", []):
        if not isinstance(outbound, dict) or outbound.get("tag") != exclusive_tag:
            continue
        vnext = outbound.get("settings", {}).get("vnext", [{}])
        if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
            actual_server = str(vnext[0].get("address") or "")
            actual_port = int(vnext[0].get("port") or 0)

    tags_ok = set(actual_tags) == set(expected_tags)
    forbidden_ok = not forbidden_present
    server_ok = actual_port == expected_port and (
        actual_server in expected_servers if expected_servers else bool(actual_server)
    )
    ok = tags_ok and forbidden_ok and server_ok
    details = [
        f"outbounds {','.join(actual_tags) or 'none'}",
        f"server {actual_server}:{actual_port}" if actual_server else "server missing",
    ]
    if forbidden_present:
        details.append(f"forbidden {','.join(forbidden_present)}")
    return [SelfCheck(
        name=name,
        ok=ok,
        status="ok" if ok else "fail",
        detail="; ".join(details),
    )]


def collect_trojan_ws_config_check(policy: dict[str, Any]) -> list[SelfCheck]:
    cfg = policy.get("self_trojan_ws_config")
    if not isinstance(cfg, dict):
        return []
    path = Path(str(cfg.get("path") or ""))
    name = "proxy_trojan_ws_config"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [SelfCheck(name=name, ok=False, status="fail", detail=f"{path}: {type(exc).__name__}")]

    expected_domain = str(cfg.get("expected_domain") or "")
    expected_path = str(cfg.get("expected_path") or "")
    expected_inbound_tag = str(cfg.get("expected_inbound_tag") or "")
    expected_inbound_port = int(cfg.get("expected_inbound_port") or 0)
    expected_heartbeat_period = int(cfg.get("expected_heartbeat_period") or 0)
    expected_loglevel = str(cfg.get("expected_loglevel") or "")
    expected_backend_tag = str(cfg.get("expected_backend_tag") or "")
    expected_backend_host = str(cfg.get("expected_backend_host") or "")
    expected_backend_port = int(cfg.get("expected_backend_port") or 0)

    inbounds = data.get("inbounds", [])
    inbound = None
    if isinstance(inbounds, list):
        for item in inbounds:
            if not isinstance(item, dict):
                continue
            if expected_inbound_tag and item.get("tag") == expected_inbound_tag:
                inbound = item
                break
            if not expected_inbound_tag and item.get("protocol") == "trojan":
                inbound = item
                break

    inbound_stream = inbound.get("streamSettings", {}) if isinstance(inbound, dict) else {}
    if not isinstance(inbound_stream, dict):
        inbound_stream = {}
    ws_settings = inbound_stream.get("wsSettings", {})
    if not isinstance(ws_settings, dict):
        ws_settings = {}
    tls_settings = inbound_stream.get("tlsSettings", {})
    if not isinstance(tls_settings, dict):
        tls_settings = {}
    cert_text = json.dumps(tls_settings.get("certificates", []), sort_keys=True)

    outbounds = data.get("outbounds", [])
    backend = None
    if isinstance(outbounds, list):
        for item in outbounds:
            if isinstance(item, dict) and item.get("tag") == expected_backend_tag:
                backend = item
                break

    backend_settings = backend.get("settings", {}) if isinstance(backend, dict) else {}
    if not isinstance(backend_settings, dict):
        backend_settings = {}
    servers = backend_settings.get("servers", [])
    first_server = servers[0] if isinstance(servers, list) and servers and isinstance(servers[0], dict) else {}
    actual_backend_host = str(first_server.get("address") or "")
    actual_backend_port = int(first_server.get("port") or 0)

    failures: list[str] = []
    if not isinstance(inbound, dict):
        failures.append("inbound missing")
    else:
        if inbound.get("protocol") != "trojan":
            failures.append("protocol")
        if expected_inbound_port and int(inbound.get("port") or 0) != expected_inbound_port:
            failures.append("port")
        if inbound_stream.get("network") != "ws":
            failures.append("network")
        if inbound_stream.get("security") != "tls":
            failures.append("tls")
        if expected_path and ws_settings.get("path") != expected_path:
            failures.append("path")
        if expected_heartbeat_period and int(ws_settings.get("heartbeatPeriod") or 0) != expected_heartbeat_period:
            failures.append("heartbeat")
        if expected_domain and expected_domain not in cert_text:
            failures.append("cert")
    if not isinstance(backend, dict):
        failures.append("backend missing")
    else:
        if backend.get("protocol") != "socks":
            failures.append("backend protocol")
        if actual_backend_host != expected_backend_host or actual_backend_port != expected_backend_port:
            failures.append("backend target")

    ok = not failures
    detail = (
        f"domain {expected_domain or 'unknown'}; "
        f"ws {ws_settings.get('path') or 'missing'}; "
        f"heartbeat {ws_settings.get('heartbeatPeriod') or 0}s; "
        f"backend {actual_backend_host or 'missing'}:{actual_backend_port or 0}"
    )
    actual_loglevel = str(data.get("log", {}).get("loglevel") or "") if isinstance(data.get("log"), dict) else ""
    if expected_loglevel and actual_loglevel != expected_loglevel:
        failures.append("loglevel")
        ok = False
        detail = f"{detail}; loglevel {actual_loglevel or 'missing'}"
    if failures:
        detail = f"{detail}; failed {','.join(failures)}"
    return [SelfCheck(
        name=name,
        ok=ok,
        status="ok" if ok else "fail",
        detail=detail,
    )]


def collect_proxy_exit_check(policy: dict[str, Any]) -> list[SelfCheck]:
    cfg = policy.get("self_proxy_exit")
    if not isinstance(cfg, dict):
        return []
    name = str(cfg.get("name") or "proxy_exit")
    host = str(cfg.get("socks_host") or "127.0.0.1")
    port = int(cfg.get("socks_port") or 0)
    url = str(cfg.get("url") or "https://ipinfo.io/ip")
    expected_ip = str(cfg.get("expected_ip") or "")
    if not port or not expected_ip:
        return []
    code, stdout = command_stdout(
        [
            "curl",
            "-4sS",
            "--socks5-hostname",
            f"{host}:{port}",
            "--connect-timeout",
            "5",
            "--max-time",
            "12",
            url,
        ],
        timeout=15,
    )
    actual_ip = stdout.splitlines()[0].strip() if stdout else ""
    ok = code == 0 and actual_ip == expected_ip
    detail = f"{actual_ip or 'empty'} via {host}:{port}, expected {expected_ip}"
    if code != 0:
        detail = f"curl exit {code}; {detail}"
    return [SelfCheck(
        name=f"proxy_exit:{name}",
        ok=ok,
        status="ok" if ok else "fail",
        detail=detail,
    )]


def collect_sync_health_checks(policy: dict[str, Any]) -> list[SelfCheck]:
    path = policy.get("self_sync_health_path")
    if not path:
        return []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        now = time.time()
        age = now - float(data.get("generated_at") or 0)
        success_age = now - float(data.get("last_success") or 0)
        switches = int(data.get("switches_24h") or 0)
    except (OSError, ValueError, TypeError):
        return [SelfCheck(name="proxy_sync_status", ok=False, status="fail", detail="status unavailable")]
    checks = [
        ("proxy_status_fresh", 0 <= age <= 900, "fail", f"status age {int(age)}s"),
        ("proxy_credentials_private", data.get("credentials_private") is True, "fail", "root-only credential files"),
        ("proxy_sync_recent", 0 <= success_age <= 7200 and not data.get("last_error"), "warn",
         f"last success {int(success_age)}s ago; error {data.get('last_error') or 'none'}"),
        ("proxy_switch_frequency", switches <= 4, "warn", f"{switches} switches in 24h"),
    ]
    return [SelfCheck(name=name, ok=ok, status="ok" if ok else severity, detail=detail)
            for name, ok, severity, detail in checks]


def collect_self_checks(config: dict[str, Any], system_metrics: dict[str, Any]) -> list[SelfCheck]:
    policy = config.get("policy", {})
    checks: list[SelfCheck] = []

    meminfo = system_metrics.get("meminfo") if isinstance(system_metrics.get("meminfo"), dict) else {}
    mem_total = int(meminfo.get("MemTotal") or 0)
    mem_available = int(meminfo.get("MemAvailable") or 0)
    if mem_total > 0:
        pct = mem_available / mem_total
        checks.append(SelfCheck(
            name="memory_available",
            ok=pct >= float(policy.get("self_min_mem_available_ratio", 0.12)),
            status="ok" if pct >= float(policy.get("self_min_mem_available_ratio", 0.12)) else "warn",
            detail=f"{mem_available // (1024 * 1024)}MiB available of {mem_total // (1024 * 1024)}MiB",
        ))

    disk = system_metrics.get("disk_root") if isinstance(system_metrics.get("disk_root"), dict) else {}
    disk_total = int(disk.get("total") or 0)
    disk_free = int(disk.get("free") or 0)
    if disk_total > 0:
        pct = disk_free / disk_total
        checks.append(SelfCheck(
            name="disk_root_free",
            ok=pct >= float(policy.get("self_min_disk_free_ratio", 0.10)),
            status="ok" if pct >= float(policy.get("self_min_disk_free_ratio", 0.10)) else "fail",
            detail=f"{disk_free // (1024 * 1024)}MiB free of {disk_total // (1024 * 1024)}MiB",
        ))

    loadavg = system_metrics.get("loadavg")
    if isinstance(loadavg, (list, tuple)) and loadavg:
        cpu_count = max(1, os.cpu_count() or 1)
        threshold = float(policy.get("self_max_load_per_cpu", 1.5)) * cpu_count
        one_min = float(loadavg[0])
        checks.append(SelfCheck(
            name="load_average",
            ok=one_min <= threshold,
            status="ok" if one_min <= threshold else "warn",
            detail=f"1m load {one_min:.2f}, threshold {threshold:.2f}",
        ))

    timers = list(policy.get("self_expected_timers", []))
    for unit in timers:
        status = systemctl_is_active(str(unit))
        checks.append(SelfCheck(
            name=f"timer:{unit}",
            ok=status == "active",
            status="ok" if status == "active" else "fail",
            detail=status,
        ))

    services = list(policy.get("self_expected_services", []))
    for unit in services:
        status = systemctl_is_active(str(unit))
        checks.append(SelfCheck(
            name=f"service:{unit}",
            ok=status == "active",
            status="ok" if status == "active" else "fail",
            detail=status,
        ))

    checks.extend(collect_listener_checks(policy))
    checks.extend(collect_xray_config_check(policy))
    checks.extend(collect_trojan_ws_config_check(policy))
    checks.extend(collect_proxy_exit_check(policy))
    checks.extend(collect_sync_health_checks(policy))
    dashboard_url = policy.get("self_dashboard_url")
    if dashboard_url:
        try:
            request = urllib.request.Request(str(dashboard_url), method="HEAD", headers={"User-Agent": DEFAULT_USER_AGENT})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=8) as response:
                ok = response.status == 200 and response.headers.get("X-Watchtower-App") == "dashboard-v2"
                detail = f"HTTPS status {response.status}; authenticated origin {'verified' if ok else 'unverified'}"
        except urllib.error.HTTPError as exc:
            ok, detail = False, f"HTTPS status {exc.code}"
        except Exception as exc:
            ok, detail = False, type(exc).__name__
        checks.append(SelfCheck(name="dashboard_public_ingress", ok=ok, status="ok" if ok else "fail", detail=detail))

    return checks


def repo_to_dict(repo: RepoSummary) -> dict[str, Any]:
    return dataclasses.asdict(repo)


def result_to_dict(result: UrlResult) -> dict[str, Any]:
    return dataclasses.asdict(result)


def check_to_dict(check: GitHubRepoCheck) -> dict[str, Any]:
    return dataclasses.asdict(check)


def self_check_to_dict(check: SelfCheck) -> dict[str, Any]:
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
    self_checks: list[SelfCheck] | None = None,
    slow_url_ms: int = 8000,
) -> dict[str, Any]:
    self_checks = self_checks or []
    failed_urls = [r for r in url_results if not r.ok]
    failed_critical_urls = [r for r in failed_urls if r.critical]
    failed_observed_urls = [r for r in failed_urls if not r.critical]
    slow_urls = [r for r in url_results if r.ok and r.elapsed_ms > slow_url_ms]
    stale_repos = [r for r in repos if (staleness_days(r.pushed_at) or 0) > 365 and not r.archived]
    cert_warnings = [
        r for r in url_results if r.tls_days_remaining is not None and r.tls_days_remaining < 30
    ]
    failed_repo_checks = [c for c in repo_checks if not c.ok and c.status not in {"missing", "skipped"}]
    failed_self_checks = [c for c in self_checks if not c.ok and c.status == "fail"]
    warning_self_checks = [c for c in self_checks if not c.ok and c.status != "fail"]
    status = "ok"
    if failed_critical_urls or failed_self_checks:
        status = "fail"
    elif failed_observed_urls or slow_urls or cert_warnings or failed_repo_checks or warning_self_checks or github_meta.get("error"):
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
        "self_check_count": len(self_checks),
        "failed_self_check_count": len(failed_self_checks),
        "warning_self_check_count": len(warning_self_checks),
        "slow_url_ms": slow_url_ms,
        "status": status,
    }


def startup_to_dict(startup: VentureDexStartup) -> dict[str, Any]:
    return dataclasses.asdict(startup)


def build_targets(
    config: dict[str, Any],
    repos: list[RepoSummary],
    mode: str,
    discovered_targets: list[UrlTarget],
) -> tuple[list[UrlTarget], list[str]]:
    policy = config.get("policy", {})
    explicit = [
        UrlTarget(url=url, source="explicit", repo=None, critical=True)
        for url in list(config.get("urls", []))
    ]
    if mode in {"core", "self"}:
        return filter_allowed_targets(explicit if mode != "self" else [], config)

    repo_candidates = repos
    if mode == "github-lite":
        limit = max(1, int(policy.get("github_lite_repo_targets", 16)))
        repo_candidates = [repo for repo in sorted_recent_repos(repos) if not repo.archived and not repo.fork][:limit]

    repo_targets: list[UrlTarget] = []
    for repo in repo_candidates:
        if repo.url:
            repo_targets.append(UrlTarget(url=repo.url, source="github_repo", repo=repo.name, critical=False))
        if repo.homepage:
            repo_targets.append(UrlTarget(url=repo.homepage, source="repo_homepage", repo=repo.name, critical=False))
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


def atomic_write_text(path: Path, text: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".watchtower-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def write_reports(output_dir: Path, report: dict[str, Any], keep: int = 2000) -> None:
    ensure_dir(output_dir)
    latest_json = output_dir / "latest.json"
    latest_md = output_dir / "latest.md"
    run_id = report["run"]["id"]
    archive_json = output_dir / f"{run_id}.json"
    archive_md = output_dir / f"{run_id}.md"
    json_text = json.dumps(report, indent=2, sort_keys=True)
    md_text = render_markdown(report)
    atomic_write_text(latest_json, json_text + "\n")
    atomic_write_text(latest_md, md_text)
    atomic_write_text(archive_json, json_text + "\n")
    atomic_write_text(archive_md, md_text)
    atomic_write_text(output_dir / "index.html", render_dashboard(output_dir, report))
    cleanup_old_reports(output_dir, keep=keep)


def report_mode(report: dict[str, Any]) -> str:
    return str(report.get("run", {}).get("mode") or "unknown")


def load_latest_reports_by_mode(output_dir: Path, current: dict[str, Any]) -> dict[str, dict[str, Any]]:
    reports: dict[str, tuple[float, dict[str, Any]]] = {report_mode(current): (time.time(), current)}
    for path in output_dir.glob("*.json"):
        if path.name == "latest.json":
            continue
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            mtime = path.stat().st_mtime
        except Exception:
            continue
        mode = report_mode(item)
        if mode not in reports or mtime > reports[mode][0]:
            reports[mode] = (mtime, item)
    return {mode: item for mode, (_mtime, item) in reports.items()}


def dashboard_class(status: str | None) -> str:
    normalized = str(status or "").lower()
    if normalized in {"ok", "active", "healthy", "success"}:
        return "ok"
    if normalized in {"fail", "failed", "failure", "error", "inactive"}:
        return "fail"
    if normalized in {"warn", "warning", "degraded", "busy"}:
        return "warn"
    return "muted"


def safe_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def fmt_number(value: Any) -> str:
    return f"{safe_int(value):,}"


def fmt_bytes(value: Any) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "-"
    units = ["B", "KiB", "MiB", "GiB"]
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return "-"


def fmt_time(value: Any) -> str:
    if not value:
        return "-"
    return str(value).replace("T", " ").replace("+00:00", " UTC").replace("Z", " UTC")


def fmt_percent(part: Any, total: Any) -> str:
    denominator = safe_float(total)
    if denominator <= 0:
        return "-"
    pct = max(0.0, min(100.0, safe_float(part) / denominator * 100.0))
    return f"{pct:.0f}%"


def dashboard_percent(part: Any, total: Any) -> float:
    denominator = safe_float(total)
    if denominator <= 0:
        return 0.0
    return max(0.0, min(100.0, safe_float(part) / denominator * 100.0))


DASHBOARD_CSS = """
    :root {
      color-scheme: light dark;
      --bg: #f7f7f2;
      --surface: #ffffff;
      --surface-subtle: #f3f5f0;
      --text: #1c1f23;
      --muted: #667085;
      --border: #d8ded2;
      --primary: #2563eb;
      --success: #16823a;
      --warning: #b45309;
      --danger: #c0262d;
      --teal: #0f766e;
      --shadow: 0 12px 32px rgba(28, 31, 35, 0.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }
    a { color: inherit; }
    .app-shell {
      width: min(1240px, calc(100% - 32px));
      margin: 0 auto;
      padding: 24px 0 44px;
    }
    .topbar {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 18px;
      padding: 6px 0 18px;
    }
    .eyebrow {
      margin: 0 0 6px;
      color: var(--teal);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .08em;
      text-transform: uppercase;
    }
    h1 {
      margin: 0;
      font-size: clamp(26px, 3vw, 34px);
      line-height: 1.12;
      letter-spacing: 0;
    }
    h2 {
      margin: 28px 0 12px;
      font-size: 17px;
      letter-spacing: 0;
    }
    .top-meta {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      flex-wrap: wrap;
      gap: 8px;
      color: var(--muted);
      font-size: 13px;
    }
    .link-pill {
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 5px 10px;
      text-decoration: none;
      background: var(--surface);
      font-weight: 700;
      color: var(--text);
    }
    .lang-switch {
      display: inline-flex;
      overflow: hidden;
      border: 1px solid var(--border);
      border-radius: 999px;
      background: var(--surface);
    }
    .lang-switch button {
      min-width: 42px;
      border: 0;
      border-right: 1px solid var(--border);
      background: transparent;
      color: var(--muted);
      cursor: pointer;
      font: inherit;
      font-size: 12px;
      font-weight: 800;
      padding: 6px 10px;
    }
    .lang-switch button:last-child { border-right: 0; }
    .lang-switch button[aria-pressed="true"] {
      background: var(--text);
      color: var(--surface);
    }
    .status-band {
      --accent: var(--primary);
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 18px;
      align-items: center;
      border: 1px solid var(--border);
      border-left: 4px solid var(--accent);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: var(--shadow);
      padding: 16px;
    }
    .tone-ok { --accent: var(--success); }
    .tone-warn { --accent: var(--warning); }
    .tone-fail { --accent: var(--danger); }
    .tone-muted { --accent: var(--primary); }
    .status-title {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 6px;
    }
    .status-title strong {
      font-size: 20px;
      line-height: 1.2;
    }
    .status-copy {
      color: var(--muted);
      font-size: 14px;
      line-height: 1.45;
    }
    .status-facts {
      display: grid;
      grid-template-columns: repeat(2, minmax(110px, 1fr));
      gap: 8px;
      min-width: min(420px, 100%);
    }
    .fact {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface-subtle);
      padding: 9px 10px;
    }
    .fact span {
      display: block;
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: .06em;
      text-transform: uppercase;
    }
    .fact strong {
      display: block;
      margin-top: 4px;
      font-size: 13px;
      line-height: 1.3;
      word-break: break-word;
    }
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 10px;
      margin-top: 16px;
    }
    .metric-card {
      --accent: var(--primary);
      min-width: 0;
      border: 1px solid var(--border);
      border-top: 3px solid var(--accent);
      border-radius: 8px;
      background: var(--surface);
      padding: 13px;
    }
    .metric-label {
      color: var(--muted);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .04em;
      text-transform: uppercase;
    }
    .metric-value {
      margin-top: 8px;
      font-size: 23px;
      font-weight: 800;
      line-height: 1.08;
      overflow-wrap: anywhere;
    }
    .metric-detail {
      min-height: 34px;
      margin-top: 6px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.35;
    }
    .progress {
      height: 6px;
      overflow: hidden;
      border-radius: 999px;
      background: var(--surface-subtle);
      margin-top: 10px;
    }
    .progress span {
      display: block;
      width: var(--progress);
      height: 100%;
      background: var(--accent);
    }
    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-top: 28px;
    }
    .section-header h2 {
      margin: 0;
    }
    .section-header small {
      color: var(--muted);
      font-size: 12px;
      text-align: right;
    }
    .table-shell {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface);
    }
    table {
      width: 100%;
      min-width: 840px;
      border-collapse: collapse;
    }
    th, td {
      padding: 11px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
      font-size: 13px;
    }
    th {
      background: var(--surface-subtle);
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: .06em;
      text-transform: uppercase;
      white-space: nowrap;
    }
    tr:last-child td { border-bottom: 0; }
    td small {
      display: block;
      margin-top: 4px;
      color: var(--muted);
      font-size: 11px;
    }
    .mode-name {
      font-weight: 800;
      white-space: nowrap;
    }
    .nowrap { white-space: nowrap; }
    .chip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 46px;
      border-radius: 999px;
      padding: 4px 9px;
      color: #fff;
      font-size: 12px;
      font-weight: 800;
      line-height: 1;
      text-transform: capitalize;
      white-space: nowrap;
    }
    .chip.ok { background: var(--success); }
    .chip.warn { background: var(--warning); }
    .chip.fail { background: var(--danger); }
    .chip.muted { background: #697586; }
    .service-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(270px, 1fr));
      gap: 10px;
    }
    .service-card {
      --accent: var(--primary);
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
      gap: 10px;
      align-items: start;
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent);
      border-radius: 8px;
      background: var(--surface);
      padding: 11px;
    }
    .service-card strong {
      display: block;
      font-size: 13px;
      overflow-wrap: anywhere;
    }
    .service-card small {
      display: block;
      margin-top: 4px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .issue-list {
      display: grid;
      gap: 8px;
      margin: 0;
      padding: 0;
      list-style: none;
    }
    .issue-item {
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
      gap: 10px;
      align-items: start;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface);
      padding: 11px;
    }
    .issue-item strong,
    .issue-item small,
    .issue-item code {
      display: block;
    }
    .issue-item strong {
      font-size: 13px;
      overflow-wrap: anywhere;
    }
    .issue-item small {
      margin-top: 3px;
      color: var(--muted);
      font-size: 11px;
    }
    .issue-item code {
      margin-top: 6px;
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      line-height: 1.35;
      white-space: normal;
      overflow-wrap: anywhere;
    }
    .empty-state {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface);
      padding: 16px;
      color: var(--muted);
      font-size: 13px;
    }
    @media (max-width: 720px) {
      .app-shell { width: min(100% - 20px, 1240px); padding-top: 14px; }
      .topbar,
      .status-band {
        display: grid;
        grid-template-columns: 1fr;
      }
      .topbar { align-items: start; }
      .top-meta { justify-content: flex-start; }
      .status-facts {
        grid-template-columns: 1fr;
        min-width: 0;
      }
      .metric-grid {
        grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
      }
      .metric-value { font-size: 20px; }
      .section-header {
        align-items: flex-start;
        flex-direction: column;
      }
      .section-header small { text-align: left; }
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #10120f;
        --surface: #181b17;
        --surface-subtle: #20251e;
        --text: #ecefeb;
        --muted: #a8b2a1;
        --border: #343b31;
        --primary: #70a5ff;
        --success: #3fbf68;
        --warning: #d89b37;
        --danger: #ee6468;
        --teal: #46b7a9;
        --shadow: none;
      }
      .link-pill { background: var(--surface-subtle); }
    }
"""


DASHBOARD_JS = """
    (() => {
      const root = document.documentElement;
      const choices = Array.from(document.querySelectorAll("[data-lang-choice]"));
      const translatable = Array.from(document.querySelectorAll("[data-en][data-zh]"));
      const stored = localStorage.getItem("watchtower-lang");
      const query = new URLSearchParams(location.search).get("lang");
      const browser = navigator.language && navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en";
      const initial = query === "zh" || query === "en" ? query : stored || browser;

      function setLanguage(lang) {
        const next = lang === "zh" ? "zh" : "en";
        root.lang = next === "zh" ? "zh-CN" : "en";
        root.dataset.lang = next;
        localStorage.setItem("watchtower-lang", next);
        translatable.forEach((node) => {
          node.textContent = node.dataset[next] || node.dataset.en || "";
        });
        choices.forEach((button) => {
          const active = button.dataset.langChoice === next;
          button.setAttribute("aria-pressed", active ? "true" : "false");
        });
      }

      choices.forEach((button) => {
        button.addEventListener("click", () => setLanguage(button.dataset.langChoice));
      });
      setLanguage(initial);
    })();
"""


LOCKED_DASHBOARD_CSS = """
    :root {
      color-scheme: light dark;
      --bg: #f5f6f1;
      --surface: #ffffff;
      --text: #1c1f23;
      --muted: #667085;
      --border: #d8ded2;
      --accent: #0f766e;
      --danger: #c0262d;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      padding: 20px;
      letter-spacing: 0;
    }
    main {
      width: min(760px, 100%);
      border: 1px solid var(--border);
      border-radius: 10px;
      background: var(--surface);
      padding: clamp(24px, 5vw, 44px);
      box-shadow: 0 18px 60px rgba(28, 31, 35, 0.1);
    }
    .eyebrow {
      margin: 0 0 10px;
      color: var(--accent);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .08em;
      text-transform: uppercase;
    }
    h1 {
      margin: 0;
      font-size: clamp(30px, 6vw, 50px);
      line-height: 1.04;
      letter-spacing: 0;
    }
    .lead {
      margin: 18px 0 0;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.7;
    }
    .notice {
      margin: 22px 0;
      border: 1px solid var(--border);
      border-left: 4px solid var(--accent);
      border-radius: 8px;
      padding: 14px 16px;
      color: var(--muted);
      line-height: 1.65;
      font-size: 14px;
      background: color-mix(in srgb, var(--surface), var(--bg) 45%);
    }
    form {
      display: grid;
      gap: 10px;
      margin-top: 22px;
    }
    label {
      color: var(--muted);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .05em;
      text-transform: uppercase;
    }
    .form-row {
      display: flex;
      gap: 8px;
    }
    input {
      min-width: 0;
      flex: 1;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface);
      color: var(--text);
      font: inherit;
      padding: 12px 13px;
    }
    button {
      border: 0;
      border-radius: 8px;
      background: var(--text);
      color: var(--surface);
      cursor: pointer;
      font: inherit;
      font-weight: 800;
      padding: 12px 16px;
      white-space: nowrap;
    }
    .error {
      color: var(--danger);
      font-size: 13px;
      font-weight: 700;
      margin: 4px 0 0;
    }
    .fine-print {
      margin: 18px 0 0;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.6;
    }
    @media (max-width: 560px) {
      .form-row { flex-direction: column; }
      button { width: 100%; }
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #10120f;
        --surface: #181b17;
        --text: #ecefeb;
        --muted: #a8b2a1;
        --border: #343b31;
        --accent: #46b7a9;
        --danger: #ee6468;
      }
    }
"""


def dashboard_password() -> str:
    plain = os.environ.get("WATCHTOWER_DASHBOARD_PASSWORD")
    if plain:
        return plain
    encoded = os.environ.get("WATCHTOWER_DASHBOARD_PASSWORD_B64")
    if not encoded:
        return ""
    try:
        return base64.b64decode(encoded).decode("utf-8")
    except Exception:
        return ""


def render_locked_dashboard(error: bool = False) -> str:
    error_html = (
        "<p class='error'>密码不正确，请确认你有授权后再重试。 / Invalid password.</p>"
        if error
        else ""
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Project Watchtower</title>
  <style>{LOCKED_DASHBOARD_CSS}</style>
</head>
<body>
<main>
  <p class="eyebrow">Project Watchtower</p>
  <h1>即将开启的运维状态入口</h1>
  <p class="lead">
    这是一个受限的服务器自检与项目可用性监控页面。详细状态、服务计数、网络指标和报告文件仅向授权人员开放。
  </p>
  <div class="notice">
    为避免误解和滥用：本站不提供代理、下载、流量中转、压力测试、爬取服务或任何第三方内容分发能力。
    未授权访问不会显示内部监控细节；异常请求可能被记录用于安全审计。
    <br>
    This endpoint is a restricted operational status surface. It is not a proxy,
    hosting service, traffic generator, scraper, or public API.
  </div>
  <form method="post" action="/login" autocomplete="off">
    <label for="password">授权密码 / Access password</label>
    <div class="form-row">
      <input id="password" name="password" type="password" required autofocus>
      <button type="submit">查看详情</button>
    </div>
    {error_html}
  </form>
  <p class="fine-print">
    如果你不是该实例的维护者，请停止尝试访问。If you are not the operator of this instance,
    do not attempt to access restricted operational details.
  </p>
</main>
</body>
</html>
"""


def render_dashboard(output_dir: Path, current: dict[str, Any]) -> str:
    reports = load_latest_reports_by_mode(output_dir, current)
    mode_order = ["core", "self", "github-lite", "venture-check", "venture-discover", "daily", "weekly"]
    allowed_modes = set(RUN_MODES) | {report_mode(current)}
    reports = {mode: report for mode, report in reports.items() if mode in allowed_modes}
    ordered_modes = [mode for mode in mode_order if mode in reports] + sorted(set(reports) - set(mode_order))
    latest_self = reports.get("self") or current
    system = latest_self.get("system") if isinstance(latest_self.get("system"), dict) else {}
    mem = system.get("meminfo") if isinstance(system.get("meminfo"), dict) else {}
    disk = system.get("disk_root") if isinstance(system.get("disk_root"), dict) else {}
    loadavg = system.get("loadavg") or []

    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else "-"))

    def attr(value: Any) -> str:
        return html.escape(str(value if value is not None else "-"), quote=True)

    def dual(en: Any, zh: Any, tag: str = "span", attrs: str = "") -> str:
        return f"<{tag}{attrs} data-en=\"{attr(en)}\" data-zh=\"{attr(zh)}\">{esc(en)}</{tag}>"

    def status_label(status: str) -> tuple[str, str]:
        normalized = dashboard_class(status)
        return {
            "ok": ("ok", "正常"),
            "warn": ("warn", "注意"),
            "fail": ("fail", "故障"),
            "muted": (str(status or "unknown"), "未知"),
        }[normalized]

    summaries = [
        report.get("summary")
        for report in (reports[mode] for mode in ordered_modes)
        if isinstance(report.get("summary"), dict)
    ]
    ok_count = sum(1 for summary in summaries if summary.get("status") == "ok")
    warn_count = sum(1 for summary in summaries if summary.get("status") == "warn")
    fail_count = sum(1 for summary in summaries if summary.get("status") == "fail")
    total_urls = sum(safe_int(summary.get("url_count")) for summary in summaries)
    total_url_failures = sum(safe_int(summary.get("failed_url_count")) for summary in summaries)
    total_critical_url_failures = sum(safe_int(summary.get("failed_critical_url_count")) for summary in summaries)
    total_self_failures = sum(safe_int(summary.get("failed_self_check_count")) for summary in summaries)
    total_repo_failures = sum(safe_int(summary.get("failed_repo_check_count")) for summary in summaries)
    total_failures = total_url_failures + total_self_failures + total_repo_failures
    total_bytes_read = sum(
        safe_int((reports[mode].get("resource_budget") or {}).get("bytes_read"))
        for mode in ordered_modes
        if isinstance(reports[mode].get("resource_budget"), dict)
    )
    overall_status = "fail" if fail_count else "warn" if warn_count else "ok"
    overall_labels = {
        "ok": ("Healthy", "运行正常"),
        "warn": ("Needs attention", "需要关注"),
        "fail": ("Failing", "存在故障"),
    }
    overall_label_en, overall_label_zh = overall_labels[overall_status]

    cpu_count = max(1, safe_int(system.get("cpu_count")) or (os.cpu_count() or 1))
    one_min_load = safe_float(loadavg[0]) if isinstance(loadavg, (list, tuple)) and loadavg else 0.0
    load_text = ", ".join(f"{safe_float(v):.2f}" for v in loadavg[:3]) if isinstance(loadavg, (list, tuple)) else "-"
    mem_available = safe_int(mem.get("MemAvailable"))
    mem_total = safe_int(mem.get("MemTotal"))
    disk_free = safe_int(disk.get("free"))
    disk_total = safe_int(disk.get("total"))
    mem_pct = dashboard_percent(mem_available, mem_total)
    disk_pct = dashboard_percent(disk_free, disk_total)
    raw_load_pct = one_min_load / cpu_count * 100.0 if cpu_count else 0.0
    load_pct = max(0.0, min(100.0, raw_load_pct))
    memory_value = fmt_bytes(mem_available) if mem_total > 0 else "-"
    memory_detail_en = f"{fmt_percent(mem_available, mem_total)} available of {fmt_bytes(mem_total)}" if mem_total > 0 else "not reported"
    memory_detail_zh = f"{fmt_percent(mem_available, mem_total)} 可用，共 {fmt_bytes(mem_total)}" if mem_total > 0 else "未上报"
    memory_tone = "ok" if mem_pct >= 25 else "warn" if mem_pct >= 12 else "fail" if mem_total > 0 else "muted"
    disk_tone = "ok" if disk_pct >= 25 else "warn" if disk_pct >= 10 else "fail" if disk_total > 0 else "muted"
    load_tone = "ok" if raw_load_pct <= 75 else "warn" if raw_load_pct <= 120 else "fail" if loadavg else "muted"
    networks = system.get("network_interfaces") if isinstance(system.get("network_interfaces"), dict) else {}
    public_networks = {
        name: data
        for name, data in networks.items()
        if name != "lo" and isinstance(data, dict)
    }
    rx_total = sum(safe_int(data.get("rx_bytes")) for data in public_networks.values())
    tx_total = sum(safe_int(data.get("tx_bytes")) for data in public_networks.values())

    def progress_bar(label: str, pct: float) -> str:
        return (
            f"<div class='progress' aria-label='{esc(label)}'>"
            f"<span style='--progress:{pct:.1f}%'></span>"
            "</div>"
        )

    def metric_card(
        label_en: str,
        label_zh: str,
        value_html: str,
        detail_en: str,
        detail_zh: str,
        tone: str = "muted",
        progress: float | None = None,
    ) -> str:
        progress_html = progress_bar(label_en, progress) if progress is not None else ""
        label_html = dual(label_en, label_zh, "div", " class='metric-label'")
        detail_html = dual(detail_en, detail_zh, "div", " class='metric-detail'")
        return (
            f"<article class='metric-card tone-{dashboard_class(tone)}'>"
            f"{label_html}"
            f"<div class='metric-value'>{value_html}</div>"
            f"{detail_html}"
            f"{progress_html}"
            "</article>"
        )

    metric_cards = [
        metric_card(
            "Overall",
            "总体状态",
            dual(overall_label_en, overall_label_zh, "span", f" class='chip {overall_status}'"),
            f"{ok_count} ok / {warn_count} warn / {fail_count} fail",
            f"{ok_count} 正常 / {warn_count} 注意 / {fail_count} 故障",
            overall_status,
        ),
        metric_card(
            "URL Checks",
            "URL 检测",
            esc(fmt_number(total_urls)),
            f"{fmt_number(total_url_failures)} failing, {fmt_number(total_critical_url_failures)} critical",
            f"{fmt_number(total_url_failures)} 个异常，{fmt_number(total_critical_url_failures)} 个关键异常",
            "fail" if total_critical_url_failures else "warn" if total_url_failures else "ok",
        ),
        metric_card(
            "Service Issues",
            "服务问题",
            esc(fmt_number(total_self_failures)),
            f"{fmt_number(total_repo_failures)} GitHub repo check issues",
            f"{fmt_number(total_repo_failures)} 个 GitHub 仓库检查问题",
            "fail" if total_self_failures else "warn" if total_repo_failures else "ok",
        ),
        metric_card(
            "Traffic Read",
            "读取流量",
            esc(fmt_bytes(total_bytes_read)),
            "bounded body bytes across latest reports",
            "最新报告累计读取的受限正文流量",
            "muted",
        ),
        metric_card(
            "Memory",
            "内存",
            esc(memory_value),
            memory_detail_en,
            memory_detail_zh,
            memory_tone,
            mem_pct if mem_total > 0 else None,
        ),
        metric_card(
            "Disk",
            "磁盘",
            esc(fmt_bytes(disk_free)),
            f"{fmt_percent(disk_free, disk_total)} free of {fmt_bytes(disk_total)}",
            f"{fmt_percent(disk_free, disk_total)} 可用，共 {fmt_bytes(disk_total)}",
            disk_tone,
            disk_pct if disk_total > 0 else None,
        ),
        metric_card(
            "CPU Load",
            "CPU 负载",
            esc(f"{one_min_load:.2f}"),
            f"{cpu_count} CPU, load averages {load_text}",
            f"{cpu_count} 核，平均负载 {load_text}",
            load_tone,
            load_pct if loadavg else None,
        ),
        metric_card(
            "Network",
            "网络",
            esc(fmt_bytes(rx_total + tx_total)),
            f"RX {fmt_bytes(rx_total)} / TX {fmt_bytes(tx_total)} cumulative",
            f"累计接收 {fmt_bytes(rx_total)} / 发送 {fmt_bytes(tx_total)}",
            "muted",
        ),
    ]

    rows: list[str] = []
    for mode in ordered_modes:
        report = reports[mode]
        summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
        budget = report.get("resource_budget") if isinstance(report.get("resource_budget"), dict) else {}
        run = report.get("run") if isinstance(report.get("run"), dict) else {}
        status = str(summary.get("status") or "unknown")
        url_failures = safe_int(summary.get("failed_url_count"))
        critical_failures = safe_int(summary.get("failed_critical_url_count"))
        repo_checks = safe_int(summary.get("repo_check_count"))
        repo_failures = safe_int(summary.get("failed_repo_check_count"))
        self_checks = safe_int(summary.get("self_check_count"))
        self_failures = safe_int(summary.get("failed_self_check_count"))
        status_en, status_zh = status_label(status)
        status_chip = dual(status_en, status_zh, "span", f" class='chip {dashboard_class(status)}'")
        critical_detail = dual(f"{critical_failures} critical", f"{critical_failures} 个关键异常", "small")
        repo_detail = dual(f"of {repo_checks} ok", f"共 {repo_checks} 个正常", "small")
        self_detail = dual(f"of {self_checks} ok", f"共 {self_checks} 个正常", "small")
        rows.append(
            f"<tr class='row-{dashboard_class(status)}'>"
            f"<td><span class='mode-name'>{esc(mode)}</span></td>"
            f"<td>{status_chip}</td>"
            f"<td class='nowrap'>{esc(fmt_time(run.get('completed_at')))}</td>"
            f"<td>{esc(fmt_number(summary.get('url_count')))}</td>"
            f"<td>{esc(fmt_number(url_failures))}{critical_detail}</td>"
            f"<td>{esc(fmt_number(repo_checks - repo_failures))}{repo_detail}</td>"
            f"<td>{esc(fmt_number(self_checks - self_failures))}{self_detail}</td>"
            f"<td>{esc(fmt_bytes(budget.get('bytes_read')))}</td>"
            "</tr>"
        )

    service_checks = [
        check
        for check in (latest_self.get("self_checks", []) or [])
        if isinstance(check, dict)
    ]
    service_checks.sort(key=lambda check: {"fail": 0, "warn": 1, "ok": 2}.get(dashboard_class(str(check.get("status"))), 3))
    service_cards: list[str] = []
    for check in service_checks:
        name = str(check.get("name") or "")
        status = str(check.get("status") or ("ok" if check.get("ok") else "warn"))
        status_en, status_zh = status_label(status)
        status_chip = dual(status_en, status_zh, "span", f" class='chip {dashboard_class(status)}'")
        service_cards.append(
            f"<article class='service-card tone-{dashboard_class(status)}'>"
            f"{status_chip}"
            f"<div><strong>{esc(name)}</strong><small>{esc(check.get('detail') or '')}</small></div>"
            "</article>"
        )

    issues: list[tuple[str, str, str, str, str]] = []
    for check in service_checks:
        if check.get("ok"):
            continue
        tone = dashboard_class(str(check.get("status") or "warn"))
        issues.append((tone, "self", "service", str(check.get("name") or ""), str(check.get("detail") or "")))

    for mode in ordered_modes:
        report = reports[mode]
        for item in report.get("urls", []) or []:
            if not isinstance(item, dict) or item.get("ok"):
                continue
            tone = "fail" if item.get("critical") else "warn"
            title = " ".join(part for part in [str(item.get("source") or "url"), str(item.get("repo") or "")] if part)
            detail = " - ".join(part for part in [str(item.get("url") or ""), str(item.get("error") or item.get("status") or "")] if part)
            issues.append((tone, mode, "url", title, detail))
        for check in report.get("github_repo_checks", []) or []:
            if not isinstance(check, dict) or check.get("ok"):
                continue
            title = " ".join(part for part in [str(check.get("repo") or ""), str(check.get("kind") or "")] if part)
            detail = " - ".join(part for part in [str(check.get("status") or ""), str(check.get("detail") or ""), str(check.get("url") or "")] if part)
            issues.append(("warn", mode, "github", title, detail))

    failure_items: list[str] = []
    for tone, mode, kind, title, detail in issues[:80]:
        tone_en, tone_zh = status_label(tone)
        tone_chip = dual(tone_en, tone_zh, "span", f" class='chip {tone}'")
        failure_items.append(
            "<li class='issue-item'>"
            f"{tone_chip}"
            "<div>"
            f"<strong>{esc(title or kind)}</strong>"
            f"<small>{esc(mode)} / {esc(kind)}</small>"
            f"<code>{esc(detail)}</code>"
            "</div>"
            "</li>"
        )
    if len(issues) > 80:
        more_chip = dual("more", "更多", "span", " class='chip muted'")
        failure_items.append(
            "<li class='issue-item'>"
            f"{more_chip}<div>"
            f"{dual(f'{len(issues) - 80} additional issues', f'还有 {len(issues) - 80} 个问题', 'strong')}"
            f"{dual('Open latest JSON for the full set.', '打开最新 JSON 查看完整列表。', 'small')}</div></li>"
        )
    if not failure_items:
        ok_chip = dual("ok", "正常", "span", " class='chip ok'")
        failure_items.append(
            "<li class='issue-item'>"
            f"{ok_chip}"
            f"<div>{dual('No current failures', '当前没有故障', 'strong')}"
            f"{dual('latest report per mode', '按每个模式的最新报告汇总', 'small')}</div>"
            "</li>"
        )

    network_rows: list[str] = []
    for name, data in sorted(public_networks.items()):
        network_rows.append(
            "<tr>"
            f"<td><span class='mode-name'>{esc(name)}</span></td>"
            f"<td>{esc(fmt_bytes(data.get('rx_bytes')))}</td>"
            f"<td>{esc(fmt_number(data.get('rx_packets')))}</td>"
            f"<td>{esc(fmt_bytes(data.get('tx_bytes')))}</td>"
            f"<td>{esc(fmt_number(data.get('tx_packets')))}</td>"
            "</tr>"
        )
    network_table = (
        "<div class='table-shell'><table><thead><tr>"
        f"<th>{dual('Interface', '网卡')}</th>"
        f"<th>{dual('RX Bytes', '接收字节')}</th>"
        f"<th>{dual('RX Packets', '接收包数')}</th>"
        f"<th>{dual('TX Bytes', '发送字节')}</th>"
        f"<th>{dual('TX Packets', '发送包数')}</th>"
        "</tr></thead>"
        f"<tbody>{''.join(network_rows)}</tbody></table></div>"
        if network_rows
        else f"<div class='empty-state'>{dual('No public network interface counters in the latest self report.', '最新 self 报告里没有公网网卡计数器。')}</div>"
    )

    service_section = (
        f"<div class='service-grid'>{''.join(service_cards)}</div>"
        if service_cards
        else f"<div class='empty-state'>{dual('No self-check report yet.', '还没有 self-check 报告。')}</div>"
    )
    generated = esc(fmt_time(current.get("run", {}).get("completed_at") or utc_now()))
    host = esc(system.get("hostname") or "-")
    latest_mode = esc(report_mode(current))
    mode_count = esc(fmt_number(len(ordered_modes)))
    status_copy_en = (
        f"Latest mode is {latest_mode}. Current aggregate has {fmt_number(total_urls)} URL checks, "
        f"{fmt_number(total_failures)} total issues, and {fmt_bytes(total_bytes_read)} bounded traffic read."
    )
    status_copy_zh = (
        f"最新模式是 {latest_mode}。当前汇总包含 {fmt_number(total_urls)} 个 URL 检测、"
        f"{fmt_number(total_failures)} 个问题，以及 {fmt_bytes(total_bytes_read)} 受限读取流量。"
    )

    return f"""<!doctype html>
<html lang="en" data-lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="60">
  <title>Project Watchtower</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
<main class="app-shell">
  <header class="topbar">
    <div>
      {dual('Project Watchtower', 'Project Watchtower', 'p', ' class="eyebrow"')}
      {dual('Operational Status', '运行状态', 'h1')}
    </div>
    <div class="top-meta">
      {dual(f'Generated {generated}', f'生成时间 {generated}')}
      <a class="link-pill" href="/latest.json">JSON</a>
      <a class="link-pill" href="/latest.md">Markdown</a>
      <span class="lang-switch" role="group" aria-label="Language">
        <button type="button" data-lang-choice="en" aria-pressed="true">EN</button>
        <button type="button" data-lang-choice="zh" aria-pressed="false">中文</button>
      </span>
    </div>
  </header>

  <section class="status-band tone-{overall_status}">
    <div>
      <div class="status-title">
        {dual(overall_label_en, overall_label_zh, 'span', f' class="chip {overall_status}"')}
        {dual(f'{mode_count} monitored modes', f'{mode_count} 个监控模式', 'strong')}
      </div>
      <div class="status-copy">
        {dual(status_copy_en, status_copy_zh)}
      </div>
    </div>
    <div class="status-facts">
      <div class="fact">{dual('Host', '主机', 'span')}<strong>{host}</strong></div>
      <div class="fact">{dual('Refresh', '刷新', 'span')}{dual('60 seconds', '60 秒', 'strong')}</div>
      <div class="fact">{dual('CPU', 'CPU', 'span')}{dual(f'{cpu_count} cores', f'{cpu_count} 核', 'strong')}</div>
      <div class="fact">{dual('Load', '负载', 'span')}<strong>{esc(load_text)}</strong></div>
    </div>
  </section>

  <section class="metric-grid">
    {''.join(metric_cards)}
  </section>

  <section>
    <div class="section-header">
      {dual('Mode Status', '模式状态', 'h2')}
      {dual('Newest report retained per mode', '每个模式保留的最新报告', 'small')}
    </div>
    <div class="table-shell">
      <table>
        <thead>
          <tr>
            <th>{dual('Mode', '模式')}</th>
            <th>{dual('Status', '状态')}</th>
            <th>{dual('Completed', '完成时间')}</th>
            <th>{dual('URLs', 'URL')}</th>
            <th>{dual('URL Fail', 'URL 异常')}</th>
            <th>{dual('Repo Checks', '仓库检查')}</th>
            <th>{dual('Self Checks', '自检')}</th>
            <th>{dual('Bytes', '字节')}</th>
          </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </div>
  </section>

  <section>
    <div class="section-header">
      {dual('Service Health', '服务健康', 'h2')}
      {dual('Host, timer, and proxy checks from self mode', '来自 self 模式的主机、timer 和代理检查', 'small')}
    </div>
    {service_section}
  </section>

  <section>
    <div class="section-header">
      {dual('Current Issues', '当前问题', 'h2')}
      {dual('Services, URLs, and GitHub checks', '服务、URL 和 GitHub 检查', 'small')}
    </div>
    <ul class="issue-list">{''.join(failure_items)}</ul>
  </section>

  <section>
    <div class="section-header">
      {dual('Network Interfaces', '网络接口', 'h2')}
      {dual('Cumulative counters from the latest self report', '最新 self 报告中的累计计数器', 'small')}
    </div>
    {network_table}
  </section>
</main>
<script>{DASHBOARD_JS}</script>
</body>
</html>
"""


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
    venture = report.get("venturedex") or {}
    if venture:
        lines += ["", "## VentureDex Discovery", ""]
        lines.append(f"- Source: `{venture.get('source_url')}`")
        if venture.get("cache_path"):
            lines.append(f"- Cache: `{venture.get('cache_path')}` age `{venture.get('cache_age_seconds')}` seconds")
        lines.append(f"- Profiles checked: `{venture.get('profile_pages_checked', 0)}`")
        lines.append(f"- Company URLs found: `{venture.get('company_url_count', 0)}`")
        lines.append(f"- Company targets queued: `{venture.get('company_target_count', 0)}`")
        lines.append(f"- Discovery bytes read: `{venture.get('discovery_bytes_read', 0)}`")
        errors = venture.get("discovery_errors") or []
        if errors:
            for error in errors[:10]:
                lines.append(f"- Discovery warning: `{error}`")
    self_checks = report.get("self_checks", [])
    if self_checks:
        lines += ["", "## Self Checks", ""]
        for check in self_checks[:50]:
            mark = "ok" if check.get("ok") else check.get("status", "warn")
            lines.append(f"- `{mark}` `{check.get('name')}` {check.get('detail') or ''}".rstrip())
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
    output_dir = Path(args.output_dir)
    state_dir = output_dir.resolve().parent

    started_at = utc_now()
    run_id_seed = f"{started_at}:{args.mode}:{owner}".encode("utf-8")
    run_id = hashlib.sha256(run_id_seed).hexdigest()[:12]

    venture_meta: dict[str, Any] = {}
    venture_startups: list[VentureDexStartup] = []
    self_checks: list[SelfCheck] = []
    discovered_targets: list[UrlTarget] = []
    if args.mode == "self":
        repos = []
        repo_checks = []
        rejected_urls = []
        github_meta = {"skipped": True, "reason": "self mode"}
        targets = []
    elif args.mode == "core":
        repos = []
        repo_checks = []
        github_meta = {"skipped": True, "reason": "core mode"}
        targets, rejected_urls = build_targets(config, repos, args.mode, [])
    elif args.mode == "venture-discover":
        repos = []
        repo_checks = []
        github_meta = {"skipped": True, "reason": "venture-discover mode"}
        discovered_targets, rejected_urls, venture_startups, venture_meta = collect_venturedex_targets(config, timeout)
        write_venture_cache(state_dir, venture_startups, venture_meta)
        targets = [target for target in discovered_targets if target.source == "venturedex_source"]
    elif args.mode == "venture-check":
        repos = []
        repo_checks = []
        github_meta = {"skipped": True, "reason": "venture-check mode"}
        targets, rejected_urls, venture_startups, venture_meta = collect_venture_cached_targets(config, timeout, state_dir)
    else:
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

    system_metrics = collect_system_metrics()
    if args.mode == "self":
        self_checks = collect_self_checks(config, system_metrics)

    report = {
        "run": {
            "id": run_id,
            "mode": args.mode,
            "started_at": started_at,
            "completed_at": utc_now(),
            "config": str(Path(args.config).resolve()),
        },
        "github": github_meta,
        "venturedex": venture_meta,
        "venturedex_startups": [startup_to_dict(s) for s in venture_startups],
        "summary": summarize(
            repos,
            results,
            repo_checks,
            github_meta,
            self_checks=self_checks,
            slow_url_ms=int(policy.get("slow_url_ms", 8000)),
        ),
        "repositories": [repo_to_dict(r) for r in sorted(repos, key=lambda r: r.name.lower())],
        "urls": [result_to_dict(r) for r in results],
        "github_repo_checks": [check_to_dict(c) for c in repo_checks],
        "self_checks": [self_check_to_dict(c) for c in self_checks],
        "discovered_url_count": len(discovered_targets),
        "rejected_urls": rejected_urls,
        "resource_budget": {
            "max_bytes": max_bytes,
            "bytes_read": budget.used,
            "per_request_max_bytes": per_request_limit,
            "max_concurrency": workers,
        },
        "system": system_metrics,
    }

    write_reports(output_dir, report, keep=int(policy.get("report_retention", 2000)))
    print(json.dumps({"summary": report["summary"], "output_dir": str(output_dir), "run_id": run_id}, sort_keys=True))
    return 0 if report["summary"]["status"] != "fail" or args.no_fail else 2


def serve(args: argparse.Namespace) -> int:
    from .dashboard_server import AuthState, BoundedServer, make_handler

    auth = AuthState(dashboard_password(), os.environ.get("WATCHTOWER_ORIGIN_SECRET", ""))
    public_origin = os.environ.get("WATCHTOWER_PUBLIC_ORIGIN", "https://oracle.syncany.app")
    handler = make_handler(args.output_dir, auth, render_locked_dashboard, public_origin)
    server = BoundedServer((args.host, args.port), handler)
    print(f"Serving authenticated dashboard on {args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="project-watchtower")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run a bounded health check")
    run_p.add_argument("--mode", choices=list(RUN_MODES), default="core")
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
