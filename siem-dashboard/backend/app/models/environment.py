from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from datetime import datetime, timezone
from app.database.connection import Base

class SessionEnvironment(Base):
    __tablename__ = "session_environment"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("sessions.id"))
    terminal_width = Column(Integer, nullable=True)
    terminal_height = Column(Integer, nullable=True)
    variables = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
