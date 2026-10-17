from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from app.db.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    roles = Column(String(256), nullable=False)  # comma-separated
    department = Column(String(64), nullable=False)
    failed_login_count = Column(Integer, default=0)
    last_failed_login = Column(DateTime, nullable=True)


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(64), unique=True, nullable=False, index=True)
    owner_username = Column(String(64), nullable=False)
    registered = Column(Boolean, default=True)
    os_type = Column(String(32), nullable=False)
    agent_present = Column(Boolean, default=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(64), nullable=False)
    decision = Column(String(32), nullable=False)
    user_id = Column(String(64), nullable=True)
    resource = Column(String(64), nullable=True)
    path = Column(String(256), nullable=True)
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String(16), nullable=True)
    reason = Column(Text, nullable=True)
    client_ip = Column(String(64), nullable=True)
    device_id = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class StepUpChallenge(Base):
    __tablename__ = "step_up_challenges"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    code_hash = Column(String(128), nullable=False)
    resource = Column(String(64), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    verified = Column(Boolean, default=False)
    failed_attempts = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
