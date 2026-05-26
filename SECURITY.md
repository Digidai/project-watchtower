# Security

## Threat Model

Project Watchtower is allowed to:

- call GitHub public APIs for `Digidai`
- call allowlisted Digidai-owned or Digidai-profile URLs
- write reports under its state directory
- read basic local `/proc` metrics

It is not allowed to:

- execute arbitrary SSH commands from GitHub Actions
- scan non-allowlisted hosts
- run package installation
- write outside its app and state directories
- run as root for scheduled checks

## Secrets

No secret is required for public repository inventory. A `GITHUB_TOKEN` can be
provided to raise API limits, but it should be read-only and scoped as narrowly
as possible.

The GitHub Actions SSH key must be dedicated to this project. Do not reuse your
personal SSH key.

Server-side SSH access should be restricted with the forced command in
`scripts/forced-command.sh`; the Actions key should not receive an unrestricted
shell.

## Reporting Vulnerabilities

Open a private issue or contact the repository owner directly. Do not publish
server IPs, private keys, tokens, or full reports that may contain operational
metadata.
