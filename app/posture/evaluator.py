from dataclasses import dataclass

from fastapi import Request
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import Device


@dataclass
class DevicePosture:
    device_id: str
    os_type: str
    agent_present: bool
    registered: bool
    os_supported: bool
    owner_username: str | None


def evaluate_posture(request: Request, db: Session) -> DevicePosture:
    device_id = request.headers.get("X-Device-ID", "")
    os_type = request.headers.get("X-Device-OS", "").lower()
    agent_header = request.headers.get("X-Security-Agent", "false").lower()
    agent_present = agent_header in ("true", "1", "yes")

    device = db.query(Device).filter(Device.device_id == device_id).first() if device_id else None

    if device:
        registered = device.registered
        owner = device.owner_username
        if not os_type:
            os_type = device.os_type
        if agent_header == "":
            agent_present = device.agent_present
    else:
        registered = False
        owner = None

    os_supported = os_type in settings.supported_os

    return DevicePosture(
        device_id=device_id or "unknown",
        os_type=os_type or "unknown",
        agent_present=agent_present,
        registered=registered,
        os_supported=os_supported,
        owner_username=owner,
    )
