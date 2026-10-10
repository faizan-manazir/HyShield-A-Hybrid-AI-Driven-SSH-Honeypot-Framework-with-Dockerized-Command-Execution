from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from app.database.connection import Base

class Command(Base):
    __tablename__ = "commands"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"))
    session_id = Column(Integer, ForeignKey("sessions.id"))
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    command = Column(String)
    category = Column(String, index=True)
    severity = Column(String)
    timestamp = Column(DateTime, index=True)
