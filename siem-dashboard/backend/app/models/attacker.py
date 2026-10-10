from sqlalchemy import Column, Integer, String, DateTime, Float
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database.connection import Base

class Attacker(Base):
    __tablename__ = "attackers"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, unique=True, index=True)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    total_events = Column(Integer, default=0)
    total_sessions = Column(Integer, default=0)
    threat_score = Column(Float, default=0.0)
    risk_level = Column(String, default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
