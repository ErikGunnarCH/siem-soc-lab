# Security and Sanitization

This repository documents a controlled SIEM/SOC laboratory. It must not contain real credentials, authentication material, or personal secrets.

## Never commit

- passwords or password hashes
- API keys or tokens
- Splunk authentication tokens
- session cookies
- SSH private keys
- cloud credentials
- browser secrets
- production credentials
- personally identifying secrets

## Screenshots

Before adding screenshots, review them for credentials, session identifiers, browser profile information, unrelated personal data, and sensitive hostnames or addresses. Crop or redact anything not required to demonstrate the security engineering result.

## Configuration files

Only sanitized configuration excerpts should be committed. Replace secrets with placeholders such as `<REDACTED>` or `<TOKEN>`.

## Laboratory scope

Private RFC1918 addresses and lab hostnames may appear when they materially explain the architecture, but they do not represent production systems.

## Reporting a problem

If sensitive material is accidentally committed, remove it from the current tree, rotate the affected secret if applicable, and rewrite repository history when necessary.
