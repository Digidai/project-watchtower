# Project Watchtower

Project Watchtower is a bounded monitoring agent for the public Digidai project surface.
It inventories GitHub repositories, checks known project URLs, records system/network
metrics, and writes auditable JSON/Markdown reports.
It also serves a read-only dashboard from the generated report directory.

The implementation is intentionally conservative:

- no third-party Python dependencies
- no package manager requirement on the server
- explicit host allowlist
- localhost and non-public IP literal checks for dynamically discovered hosts
- per-request timeout
- per-request and per-run byte budgets
- low concurrency
- systemd CPU and memory limits
- optional forced-command SSH for GitHub Actions

## Quick Start

Local smoke run:

```bash
python3 -m watchtower.cli run --mode core --config config/targets.json --output-dir reports --max-urls 5 --no-fail
```

Deploy to the OCI instance without using `dnf`:

```bash
WATCHTOWER_HOST=<server-ip> \
WATCHTOWER_USER=opc \
WATCHTOWER_KEY=<path-to-ssh-key> \
WATCHTOWER_AUTHORIZED_KEY="$(cat .secrets/watchtower_ed25519.pub)" \
WATCHTOWER_DASHBOARD_PASSWORD=<dashboard-password> \
./scripts/deploy.sh
```

## Modes

- `core`: checks the curated core URL list every 5 minutes with no GitHub inventory fetch.
- `self`: checks server resources and expected Watchtower timers every 5 minutes.
- `github-lite`: checks recent GitHub project health about every 15 minutes with a small API and URL budget.
- `daily`: fetches the Digidai public repository inventory, checks repo homepages, samples README links, and checks recent repo workflow status.
- `weekly`: deeper checks with a larger URL and byte budget.
- `venture-discover`: refreshes the VentureDex profile/company cache hourly.
- `venture-check`: checks a rotating cached batch of VentureDex company homepages every 10 minutes.

## Dashboard

The dashboard service serves `/var/lib/project-watchtower/reports/index.html` on HTTP port `80`.
The page aggregates the newest report per mode, self-check service state, resource metrics,
and current failures.
It is still rendered as dependency-free static HTML, with an in-page English/Chinese
language switch that stores the selected language in browser local storage.
The HTTP server disables directory listings and adds conservative response headers
for no-store caching, clickjacking protection, content-type sniffing protection,
and a self-only content security policy.
When `WATCHTOWER_DASHBOARD_PASSWORD` or `WATCHTOWER_DASHBOARD_PASSWORD_B64` is
configured, the server shows a restricted pre-launch page until the visitor signs
in. The deploy script stores the dashboard password in
`/etc/project-watchtower/dashboard.env` instead of committing it to this repository.

## Cloudflare Domain

`oracle.syncany.app` is served through a Cloudflare Worker route:

- `oracle.syncany.app/*` -> `oracle-watchtower-proxy`
- `oracle.syncany.app` -> proxied A record for the public instance IP
- `oracle-origin.syncany.app` -> DNS-only A record for the same origin IP

The Worker keeps HTTPS working at the Cloudflare edge while forwarding requests
to the dashboard's HTTP-only origin. Redeploy it after proxy changes with:

```bash
wrangler deploy --config cloudflare/wrangler.oracle.jsonc
```

## GitHub Actions Setup

Create a dedicated SSH key for GitHub Actions, add the public key to the server
for a restricted `watchtower` login, then set repository secrets:

- `WATCHTOWER_HOST`
- `WATCHTOWER_USER`
- `WATCHTOWER_PORT`
- `WATCHTOWER_SSH_KEY`
- `WATCHTOWER_KNOWN_HOSTS`

The workflow sends only approved Watchtower modes as the SSH command. On the
server, `scripts/forced-command.sh` rejects every other command. If a server-side
timer is already running, GitHub-triggered runs return a bounded `busy` response
instead of opening a shell or stacking parallel jobs.

The scheduled GitHub workflow contacts the server every 15 minutes and runs the
daily mode once per day. Server-side systemd timers also run independently, so
monitoring continues even if GitHub Actions is delayed.

Recommended key setup:

```bash
mkdir -p .secrets
ssh-keygen -t ed25519 -C project-watchtower@github -f .secrets/watchtower_ed25519 -N ""
gh secret set WATCHTOWER_SSH_KEY < .secrets/watchtower_ed25519
gh secret set WATCHTOWER_HOST --body "<server-ip>"
gh secret set WATCHTOWER_USER --body "watchtower"
gh secret set WATCHTOWER_PORT --body "22"
ssh-keyscan -t ed25519 <server-ip> | gh secret set WATCHTOWER_KNOWN_HOSTS
```

## Safety Model

This project performs real health monitoring. It does not run artificial CPU
burners, traffic generators, stress tests, mining, or unrelated third-party
traffic. The byte budget exists to prevent runaway network usage, not to create
synthetic load.

URL failures are split into critical and observed failures. Curated core URLs are
critical; repo pages, repo homepages, README-discovered links, and VentureDex
company homepages are observed so that one stale upstream URL does not make the
server itself look broken.
