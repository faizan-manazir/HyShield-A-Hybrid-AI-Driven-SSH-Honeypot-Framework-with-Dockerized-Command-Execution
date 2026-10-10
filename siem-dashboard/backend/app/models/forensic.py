from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, Boolean
from app.database.connection import Base

class ForensicLog(Base):
    __tablename__ = "forensic_logs"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("sessions.id"))
    ttylog_path = Column(String)
    shasum = Column(String)
    size = Column(Integer)
    duration = Column(Float)
    duplicate = Column(Boolean)
    timestamp = Column(DateTime)
