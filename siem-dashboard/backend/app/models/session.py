from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database.connection import Base

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    cowrie_session_id = Column(String, unique=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    src_ip = Column(String, index=True)
    src_port = Column(Integer)
    dst_ip = Column(String)
    dst_port = Column(Integer)
    protocol = Column(String)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    ended_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)
    login_success = Column(Boolean, default=False)
    command_count = Column(Integer, default=0)
    threat_score = Column(Float, default=0.0)
    risk_level = Column(String, default="LOW")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
