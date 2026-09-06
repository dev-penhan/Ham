# Ham — Cloudflare Worker Control Panel

**Ham** is a single-file, self-hosted control panel that runs entirely as a **Cloudflare Worker**. It ships with a built-in admin dashboard, user/role management, a **VLESS + Trojan (WebSocket + TLS)** proxy tunnel served directly from the Worker, subscription-link generation, Cloudflare DNS/zone management, cache purging, Telegram notifications, and D1-backed persistence — all in one `.js` file with no build step and no external server required.

> ⚠️ **Legal notice / Disclaimer**
> This project can be used to operate a VPN/proxy service. Running proxy or VPN infrastructure may be regulated or restricted in some countries. You are solely responsible for complying with your local laws, Cloudflare's Terms of Service / Acceptable Use Policy, and the terms of any service you connect to this panel. Use it only for lawful purposes and only for traffic/users you are authorized to serve.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Deployment](#deployment)
- [First-Run Setup Wizard](#first-run-setup-wizard)
- [Using the Panel](#using-the-panel)
- [Data Model (D1 Schema)](#data-model-d1-schema)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **Zero-install deployment** — one JavaScript file, pasted directly into the Cloudflare dashboard, no bundler/CLI required.
- **Built-in admin UI** — a full single-page app (HTML/CSS/JS) is served by the Worker itself; no separate frontend hosting needed.
- **Authentication & authorization**
  - Username/password login with PBKDF2 (SHA-256, 100k iterations) password hashing.
  - Session cookies (`HttpOnly`, `SameSite=Lax`, secure on HTTPS).
  - Optional two-factor login flow.
  - Role-based users (e.g. admin/viewer), user activation toggle, per-user audit trail.
  - Login rate limiting per IP.
- **VPN / proxy engine**
  - VLESS and Trojan protocols over WebSocket, tunneled through `cloudflare:sockets`.
  - Per-peer UUID/password, quota (bytes), expiry date, max concurrent IPs, port, fragmentation and mux options.
  - Configurable WebSocket path (default `/vpnws`).
  - Traffic accounting (used bytes vs. quota) and daily traffic stats.
  - Automatic link generation (`vless://…`, `trojan://…`) and Clash/subscription-compatible output.
- **Subscription links**
  - Shareable subscription tokens (per-client), each with its own protocols, ports, quota, expiry, branding/logo, and optional single-use ("one-shot") mode.
  - Base64 and Clash/YAML subscription formats.
- **Cloudflare integration**
  - Manage zones, DNS records (create/update/delete), and purge cache — directly from the panel using a Cloudflare API token.
- **Operations**
  - JSON backup/restore of the full configuration (users, VPN peers, subscriptions, settings).
  - Audit log of admin actions, with IP and timestamp.
  - Telegram bot integration for notifications (e.g. login alerts, quota/expiry alerts) and optional Telegram-based 2FA.
  - Scheduled (cron) task support for periodic maintenance (traffic aggregation, expiry checks, alerts).
  - Configurable panel name, language (English/Persian UI), and custom admin path ("camouflage" URL) to hide the login page behind an arbitrary path.
- **Bilingual UI** — interface strings are available in **English** and **Persian (فارسی)**, switchable from settings.

## Requirements

- A **Cloudflare account** with Workers enabled.
- A **Cloudflare D1 database** (free tier is sufficient to start).
- Worker **Compatibility Date** set to `2024-09-01` or later (required for `cloudflare:sockets`).
- (Optional) A Cloudflare **API Token** with Zone/DNS/Cache permissions, if you want to use the DNS and cache-purge features.
- (Optional) A **Telegram bot token** and chat ID, if you want Telegram notifications/2FA.

## Deployment

1. **Create a D1 database**
   - Cloudflare Dashboard → **Workers & Pages** → **D1** → **Create database**.
   - Give it any name (e.g. `ham-db`).

2. **Create the Worker**
   - Cloudflare Dashboard → **Workers & Pages** → **Create** → **Create Worker**.
   - Open the Worker's editor, delete the default code, and paste the entire contents of `ham.js`.

3. **Bind the D1 database**
   - In the Worker: **Settings → Bindings → Add → D1 Database**.
   - Set the **Variable name** to exactly: **`DB`**
   - Select the database you created in step 1.
   - ⚠️ If `DB` is not bound, the setup wizard will refuse to proceed.

4. **Set the Compatibility Date**
   - **Settings → Compatibility Date** → set to `2024-09-01` or a later date.
   - This is required so the `cloudflare:sockets` API (used for the VLESS/Trojan tunnel) is available.

5. **Deploy**
   - Click **Save and Deploy**.
   - The tunnel (VLESS+WS+TLS) runs on the Worker itself — no separate API token is required for the proxy to function.

6. Open your Worker's URL in a browser to start the setup wizard.

## First-Run Setup Wizard

On first visit, Ham detects that no admin account exists and walks you through setup:

1. **Create the admin account** — choose a username and a strong password (live strength hint shown in the UI), optional email.
2. **(Optional) Cloudflare API token** — paste a token to enable DNS management and cache purging from the panel.
3. **(Optional) Telegram bot token & chat ID** — enable notifications/alerts.
4. Submit — the database schema is created automatically (`meta`, `users`, `sessions`, `settings`, `audit_logs`, `login_attempts`, `vpn_peers`, `vpn_subs`, `vpn_daily`, `vpn_ips`) and you're logged in.

After setup, you can revisit **Settings** at any time to change the panel name, UI language, VPN WebSocket path, admin panel path, Cloudflare token, Telegram credentials, and proxy IP list.

## Using the Panel

- **Dashboard** — overview of users, VPN peers/subscriptions, and traffic.
- **VPN Peers** — add/edit/remove individual VLESS/Trojan clients (quota, expiry, max IPs, port, fragment/mux, location label). Each peer gets ready-to-use connection links.
- **Subscriptions** — generate a single link that bundles multiple protocols/ports for a client, with its own quota/expiry/branding, and optional one-shot (single-view) links.
- **DNS / Zones** — pick a Cloudflare zone, view/add/delete DNS records, and purge cache (single URLs or entire zone) — requires a Cloudflare API token with the right permissions.
- **Users** — create additional admin/viewer accounts, change roles, deactivate accounts, reset passwords.
- **Logs** — review the audit trail of actions taken in the panel.
- **Backup/Restore** — export the full configuration as JSON, or import a previously exported backup file.
- **Settings** — panel name, language, VPN path, camouflage/admin path, Cloudflare ports, Telegram integration, proxy IP allow-list.

## Data Model (D1 Schema)

The Worker automatically creates and migrates these tables on first run:

| Table | Purpose |
|---|---|
| `meta` | Internal key/value metadata |
| `users` | Admin/viewer accounts (hashed passwords, roles, activity flag) |
| `sessions` | Active login sessions (token, expiry, IP, user agent) |
| `settings` | Panel-wide configuration (key/value) |
| `audit_logs` | Action history for accountability |
| `login_attempts` | Per-IP login rate limiting |
| `vpn_peers` | Individual VPN client definitions and usage |
| `vpn_subs` | Subscription links bundling multiple peers/protocols |
| `vpn_daily` | Daily aggregated traffic counters |
| `vpn_ips` | Recently seen IPs per peer/subscription (for max-IP enforcement) |

## Security Notes

- Change the default admin panel path (camouflage URL) in Settings if you want to obscure the login page from casual scanning.
- Passwords are hashed with PBKDF2-SHA256 (100,000 iterations) with a per-user salt; never store or share plaintext passwords.
- Session cookies are `HttpOnly` and `Secure` (over HTTPS) — always deploy behind HTTPS (Cloudflare Workers do this by default).
- The Cloudflare API token and Telegram bot token are stored in your D1 database — restrict dashboard/database access to trusted operators only.
- Keep D1 backups (via the built-in Backup feature) somewhere safe, since they contain user records and VPN credentials.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Setup wizard won't proceed | `DB` binding missing or misspelled — must be exactly `DB` |
| VLESS/Trojan tunnel fails to connect | Compatibility Date is older than `2024-09-01`, or `cloudflare:sockets` isn't available on your plan |
| DNS/zone/cache features are disabled or error out | No Cloudflare API token set, or the token lacks the required Zone/DNS/Cache permissions |
| No Telegram alerts | Bot token/chat ID not set, or the bot hasn't been started (`/start`) with that chat |

## License

No license file was included with the source. Add a `LICENSE` file (e.g. MIT, Apache-2.0, or a proprietary notice) before publishing this repository publicly, to make the terms of use clear to others.
