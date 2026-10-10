from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from app.database.connection import Base

class ClientFingerprint(Base):
    __tablename__ = "client_fingerprints"

    id = Column(Integer, primary_key=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    session_id = Column(Integer, ForeignKey("sessions.id"))
    ssh_version = Column(String)
    hassh = Column(String)
    kex_algorithms = Column(JSON)
    encryption_algorithms = Column(JSON)
    mac_algorithms = Column(JSON)
    compression_algorithms = Column(JSON)
    timestamp = Column(DateTime)
