import asyncio
import logging
import os
from pathlib import Path
from backend.models import Event
from backend.notifications.base import NotificationProvider

log = logging.getLogger(__name__)
UPDATE_LABELS = {'scope': 'in-scope assets', 'max_bounty': 'max payout', 'impacts': 'impacts in scope', 'known_issues': 'known findings', 'details': 'program details'}

class UbuntuNotificationProvider(NotificationProvider):
    async def send(self, event: Event) -> None:
        message = event.payload.get('name') or event.payload.get('tag') or event.event_type.replace('_', ' ').title()
        if event.event_type == 'PROGRAM_UPDATED' and event.payload.get('categories'):
            message = f"{message} updated: {', '.join(UPDATE_LABELS.get(c, c) for c in event.payload['categories'])}"
        await self.send_text('Bug Bounty Tracker', str(message))

    async def send_text(self, title: str, message: str) -> bool:
        runtime = os.environ.get('XDG_RUNTIME_DIR') or f'/run/user/{os.getuid()}'
        bus = Path(runtime) / 'bus'
        if not bus.exists():
            log.warning('Ubuntu notification bus is unavailable at %s', bus)
            return False
        environment = os.environ.copy()
        environment.setdefault('XDG_RUNTIME_DIR', runtime)
        environment.setdefault('DBUS_SESSION_BUS_ADDRESS', f'unix:path={bus}')
        try:
            process = await asyncio.create_subprocess_exec('notify-send', title, message, env=environment,
                                                           stderr=asyncio.subprocess.PIPE)
            _, stderr = await process.communicate()
            if process.returncode != 0:
                log.warning('Ubuntu notification failed: %s', stderr.decode(errors='replace').strip())
                return False
            return True
        except FileNotFoundError:
            log.warning('notify-send is not installed')
            return False
