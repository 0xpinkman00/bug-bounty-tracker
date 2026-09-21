import asyncio
from backend.models import Event
from backend.notifications.base import NotificationProvider

class UbuntuNotificationProvider(NotificationProvider):
    async def send(self, event: Event) -> None:
        message = event.payload.get('name') or event.payload.get('tag') or event.event_type.replace('_', ' ').title()
        try:
            process = await asyncio.create_subprocess_exec('notify-send', 'Bug Bounty Tracker', str(message))
            await process.wait()
        except FileNotFoundError:
            pass
