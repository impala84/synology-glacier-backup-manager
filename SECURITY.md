# Security policy

Glacier Backup Manager controls access to local NAS data and an AWS destination. Treat it as privileged infrastructure and review its configuration before every deployment.

## Supported version

Only the latest commit on `main` receives security fixes.

## Reporting a vulnerability

Do not open a public issue containing credentials, private paths, bucket names, logs, or exploit details. Use GitHub's private vulnerability reporting feature for this repository. Include the affected commit, reproduction steps, likely impact, and any suggested mitigation.

## Deployment guidance

- Keep the web interface on a trusted private network or behind a correctly configured HTTPS reverse proxy and an additional access-control layer.
- Set `GBM_SECURE_COOKIES=true` whenever the application is served over HTTPS.
- Use a dedicated AWS identity with access limited to the single archive bucket and only the operations required by rclone copy and listing.
- Keep all source mounts read-only. Do not add broad writable NAS mounts to the container.
- Run the host runner as a dedicated account with read access only to the selected sources and write access only to the manager's data and log folders.
- Protect the rclone configuration and application data folders using Synology permissions. They can contain credentials, password hashes, history and private paths.
- Test both upload and restore with non-critical data before relying on the system.
- Keep an independent backup. This project is not a substitute for a tested recovery plan.

## Hardening notes

- Sources inside Synology system folders (`@…`, `#…`), the manager's own data and the rclone config folder are refused by both the web app and the runner. Existing mappings in such folders must be removed from `config.json` by hand.
- Pin the destination with the runner's `--remote`, `--bucket` and `--rclone-config` flags; `config.json` is writable by the web container.
- Set `GBM_TRUST_PROXY=true` only behind a reverse proxy you control, otherwise login throttling keys on the proxy address.
- Responses carry a restrictive Content-Security-Policy and anti-framing headers.

## Authentication

The first user creates a local administrator account. Passwords must be at least 12 characters and include uppercase, lowercase, numeric and symbol characters. They are stored using PBKDF2-SHA256 with 600,000 iterations and a random salt. Sessions use random HttpOnly, SameSite cookies, expire after 12 hours, and require a CSRF token for state-changing requests.

Password recovery requires authenticated terminal access to the Synology host. There is no email recovery service and no remote backdoor.

## Scope

The project cannot protect against a compromised Synology administrator account, a compromised host runner, overly broad AWS credentials, malicious changes to the checked-out source, or an incorrectly configured reverse proxy.

## Billing credentials

The optional billing feature reads a separate IAM user restricted to `ce:GetCostAndUsage`. The key file lives on the NAS outside the container, is refused unless mode 0600, and is read only by the host runner. The web app never sees it. Errors are redacted before display.
