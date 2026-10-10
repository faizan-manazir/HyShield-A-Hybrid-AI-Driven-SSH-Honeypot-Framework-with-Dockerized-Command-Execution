from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float
from datetime import datetime, timezone
from app.database.connection import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_code = Column(String, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"), nullable=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    title = Column(String)
    description = Column(String)
    severity = Column(String) # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String, default="OPEN") # OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    threat_score = Column(Float)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
