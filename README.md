# Bug Bounty Tracker

Local Ubuntu dashboard for bug bounty programs and GitHub repository changes.

## Run locally

Requires Docker Compose. On Ubuntu, install `libnotify-bin` to enable host desktop notifications.

```bash
cp .env.example .env
# Set GITHUB_TOKEN in .env for GitHub access.
docker compose up --build -d
```

Open **http://localhost:5173**. The API documentation is at http://localhost:8000/docs. `docker compose up` starts PostgreSQL, Redis, the backend, frontend, Celery worker, and beat. Check service status with `docker compose ps` and startup errors with `docker compose logs backend frontend`.

The Compose worker mounts your Ubuntu desktop notification bus at `${XDG_RUNTIME_DIR}/bus`. On systems where AppArmor restricts container D-Bus access, desktop notifications are blocked even though the dashboard and scheduled scans work. Run Compose from your logged-in Ubuntu desktop session. If your account is not UID/GID 1000, set `HOST_UID` and `HOST_GID` in `.env` to the output of `id -u` and `id -g`; if needed, set `XDG_RUNTIME_DIR` to your desktop session runtime directory. The app still starts on a headless session, but desktop notifications need a running user bus.

The dashboard can add repositories manually and trigger scans. Beat schedules commit and tag scans every minute; release checks run from the separate daily cron job below. Open **Sources** in the dashboard to choose Immunefi or HackenProof and start a scrape; only the selected source runs. Each source page shows progress, errors, and tracked programs. Pause and Stop take effect after the current program finishes; Resume continues from the saved program position. Immunefi uses its public catalog, while HackenProof uses public program pages; source format changes may require adapter updates. GitHub list endpoints inspect the newest 100 items per scan, so set shorter scan intervals for busy repositories.

## Poll GitHub releases at 9:00 p.m. with cron

The cron job runs a host Python task once a day at **21:00 local time**. It only checks releases; it never starts or stops Docker. The tracker PostgreSQL container must already be running so the job can save new releases. Compose exposes PostgreSQL on loopback port 5433 for this purpose. Install the job from your Ubuntu account:

```bash
python3 cron/install.py
crontab -l
tail -F ~/.local/state/bug-bounty-tracker/releases.log
```

The installer updates only its marked crontab entry and can be run again safely. Set `GITHUB_TOKEN` in `.env` for GitHub's authenticated rate limit. The **Releases** page shows only the latest run: every repository checked, releases found, errors, and whether the Ubuntu notification was sent. Each run also replaces `~/.local/state/bug-bounty-tracker/releases.log` with its timestamped text log. After the scan, the host sends one desktop summary if **New releases** is enabled in Settings and an Ubuntu desktop notification session is available. Keep the Docker stack running separately with `docker compose up --build -d`. Cron runs while you are logged out if the computer is on; it does not catch up missed jobs when the computer is off at 21:00.

## Tests

```bash
pytest -q
cd frontend && npm run build
```

No credentials are committed. GitHub access uses the `GITHUB_TOKEN` environment variable. Configure notification types on the Settings page.
