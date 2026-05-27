# Design

## Objective

Keep the OCI instance useful by making it a small, real monitoring node for the
Digidai public project ecosystem. The server periodically checks GitHub project
metadata, product URLs, certificates, response times, and local resource metrics.
Daily and weekly modes also sample README-discovered links and recent GitHub
workflow status for active non-fork repositories.
The `venture` mode uses VentureDex as a curated source list, extracts canonical
company homepages from startup profile JSON-LD, and checks those homepages every
15 minutes as observed third-party targets.

## Non-Goals

- No fake traffic generation.
- No CPU burn loops.
- No broad internet scanning.
- No unaudited remote shell from GitHub Actions.
- No `dnf` dependency for the first deployment path.

## Runtime Boundary

The server runs `/opt/project-watchtower/scripts/watchtower-run`.

Resource controls:

- `nice -n 10`
- systemd `CPUQuota=30%`
- systemd `MemoryMax=350M`
- one-process lock via `/tmp/project-watchtower.lock`
- Python request timeout and byte budget

Network controls:

- URL scheme must be HTTP or HTTPS.
- Host must match `config/targets.json` allowlist.
- Repo homepages and README-discovered links can use broader hosts, but social,
  link-shortener, and known bot-hostile hosts stay blocked.
- VentureDex-discovered company homepages can use broader hosts only when the
  URL is extracted from `https://venturedex.co/` startup profile structured data.
- Dynamically discovered targets are blocked when they use localhost-style host
  names or non-global IP literals.
- Concurrency defaults to 3.
- Per-request body read defaults to 2 MiB.
- Per-run byte budgets default to 8 MiB, 128 MiB, 384 MiB, and 96 MiB for
  light, daily, weekly, and venture mode.
- Per-mode URL caps keep expanded discovery bounded.
- GitHub detail checks use an API request budget so the server does not burn
  through unauthenticated rate limits.
- Slow URL warnings default to 8 seconds to avoid noisy alerts from normal
  third-party project sites.

## GitHub Actions Boundary

GitHub Actions should authenticate with a dedicated SSH key. The server-side
authorized key should use a forced command:

```text
command="/opt/project-watchtower/scripts/forced-command.sh",no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc ssh-ed25519 ...
```

That script accepts only `light`, `daily`, `weekly`, `venture`, and `status`.
GitHub-triggered runs tolerate a `busy` lock and return a bounded JSON response
instead of failing or stacking parallel checks.

## Reports

Reports are written under `/var/lib/project-watchtower/reports`:

- `latest.json`
- `latest.md`
- archived reports by run id

The JSON report includes:

- GitHub API metadata
- repository inventory
- URL health results
- rejected URL list
- README-discovered URL count
- GitHub README/workflow check results
- VentureDex discovery metadata and extracted company homepage targets
- local system metrics
- resource budget usage

## Reclamation Reality

Oracle documents that idle Always Free instances may be reclaimed when CPU,
network, and in some shapes memory utilization stay below thresholds over a
7-day period. This project creates legitimate periodic usage, but it does not
guarantee retention. The reliable retention path is a paid account or a real
production workload with organic traffic.
