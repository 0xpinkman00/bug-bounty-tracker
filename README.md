# Bug Bounty Tracker

Local Ubuntu dashboard for bug bounty programs and GitHub repository changes.

## Run locally

Requires Docker Compose. On Ubuntu, install `libnotify-bin` to enable host desktop notifications.

```bash
cp .env.example .env
# Set GITHUB_TOKEN in .env for GitHub access.
docker compose up --build -d
```

Open **http://bug-bounty-tracker** (mapped to `127.0.3.1` in `/etc/hosts`). The backend is not published on the host; the frontend proxies `/api` to it. `docker compose up` starts PostgreSQL, Redis, the backend, frontend, Celery worker, and beat. Check service status with `docker compose ps` and startup errors with `docker compose logs backend frontend`.

The Compose worker mounts your Ubuntu desktop notification bus at `${XDG_RUNTIME_DIR}/bus`. On systems where AppArmor restricts container D-Bus access, desktop notifications are blocked even though the dashboard and scheduled scans work. Run Compose from your logged-in Ubuntu desktop session. If your account is not UID/GID 1000, set `HOST_UID` and `HOST_GID` in `.env` to the output of `id -u` and `id -g`; if needed, set `XDG_RUNTIME_DIR` to your desktop session runtime directory. The app still starts on a headless session, but desktop notifications need a running user bus.

The dashboard can add repositories manually and trigger scans. Beat schedules commit and tag scans every minute; release checks run only when you start them (see below). Open the **Immunefi** or **HackenProof** programs page and click **Start scan** to discover programs from that source; only the selected source runs, and a progress panel appears while it does. Programs from any other platform can be added by hand on the **Other programs** page. Pause and Stop take effect after the current program finishes; Resume continues from the saved program position. Only ongoing bug bounties are tracked: Immunefi attackathons, audit competitions, bounty competitions and invite-only programs (the catalog entries with an end date) are skipped. Immunefi uses its public catalog, while HackenProof uses public program pages; source format changes may require adapter updates. GitHub list endpoints inspect the newest 100 items per scan, so set shorter scan intervals for busy repositories.

## Release checks

Release checks run only when you start them: click **Scan for new releases** at the top of the **Repositories** page, or **Stop scan** to stop after the current repository. The header shows progress while a scan runs and a summary of the last one afterwards. The watchlist lists each repository with its latest release, newest first. Only one check runs at a time. Set `GITHUB_TOKEN` in `.env` for GitHub's authenticated rate limit. After a check, the worker sends one desktop summary if **New releases** is enabled in Settings and an Ubuntu desktop notification session is available.

## Tests

```bash
pytest -q
cd frontend && npm run build
```

No credentials are committed. GitHub access uses the `GITHUB_TOKEN` environment variable. Configure notification types on the Settings page.
