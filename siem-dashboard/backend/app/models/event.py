from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from datetime import datetime, timezone
from app.database.connection import Base

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    event_uuid = Column(String, index=True, nullable=True) # Usually cowrie doesn't have uuid but we can generate one
    raw_event_type = Column(String, index=True)
    normalized_event_type = Column(String, index=True)
    timestamp = Column(DateTime, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    session_id = Column(Integer, ForeignKey("sessions.id"))
    severity = Column(String)
    message = Column(String)
    raw_json = Column(JSON)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
