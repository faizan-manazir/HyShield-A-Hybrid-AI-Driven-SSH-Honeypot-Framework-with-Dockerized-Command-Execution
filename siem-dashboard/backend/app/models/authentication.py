from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from datetime import datetime, timezone
from app.database.connection import Base

class AuthenticationAttempt(Base):
    __tablename__ = "authentication_attempts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"))
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    session_id = Column(Integer, ForeignKey("sessions.id"))
    username = Column(String, index=True)
    password = Column(String)
    result = Column(String, index=True) # FAILED, SUCCESS
    timestamp = Column(DateTime, index=True)
