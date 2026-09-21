"""Install or update the daily release poll in the current user's crontab."""

from pathlib import Path
import shlex
import subprocess

MARKER = '# bug-bounty-tracker-releases'
project = Path(__file__).resolve().parent.parent
script = project / 'cron/poll-releases.sh'
current = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
if current.returncode and 'no crontab for' not in current.stderr:
    raise SystemExit(current.stderr.strip() or 'Could not read crontab')
lines = [line for line in current.stdout.splitlines() if MARKER not in line]
lines.append(f'0 21 * * * /bin/bash {shlex.quote(str(script))} {MARKER}')
subprocess.run(['crontab', '-'], input='\n'.join(lines) + '\n', text=True, check=True)
print(f'Installed 21:00 daily cron job: {script}')
