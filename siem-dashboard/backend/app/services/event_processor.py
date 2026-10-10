import json
import logging
import uuid
import asyncio
from datetime import datetime, timezone
import dateutil.parser
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.database.connection import SessionLocal
from app.models import (
    Attacker, Session as SessionModel, Event, AuthenticationAttempt,
    Command, ClientFingerprint, ForensicLog, SessionEnvironment
)
from app.services.detection_engine import DetectionEngine
from app.services.websocket_manager import manager as ws_manager

logger = logging.getLogger(__name__)

class EventProcessor:
    def __init__(self, loop=None):
        self.loop = loop
        self.detection_engine = DetectionEngine(websocket_manager=ws_manager, loop=self.loop)

    def process_lines(self, lines: list[str]):
        db = SessionLocal()
        events_processed = []
        try:
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw_event = json.loads(line)
                    db_event = self._process_single_event(db, raw_event)
                    if db_event:
                        events_processed.append(db_event)
                except json.JSONDecodeError:
                    logger.error(f"Malformed JSON: {line}")
                except Exception as e:
                    logger.error(f"Error processing event: {e}")
            db.commit()
            
            for ev in events_processed:
                self._broadcast_event(ev)
                
        except Exception as e:
            logger.error(f"Database error during event processing: {e}")
            db.rollback()
        finally:
            db.close()

    def _broadcast_event(self, event: Event):
        if not self.loop:
            return
            
        msg = {
            "type": "new_event",
            "event": {
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.normalized_event_type,
                "raw_event_type": event.raw_event_type,
                "severity": event.severity,
                "message": event.message,
                "session_id": event.session_id,
                "attacker_id": event.attacker_id
            }
        }
        asyncio.run_coroutine_threadsafe(ws_manager.broadcast(msg), self.loop)

    def _parse_timestamp(self, ts_str: str) -> datetime:
        try:
            dt = dateutil.parser.isoparse(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.now(timezone.utc)

    def _get_or_create_attacker(self, db: Session, src_ip: str, timestamp: datetime) -> Attacker:
        attacker = db.query(Attacker).filter(Attacker.source_ip == src_ip).first()
        if not attacker:
            attacker = Attacker(source_ip=src_ip, first_seen=timestamp, last_seen=timestamp)
            db.add(attacker)
            db.flush()
        else:
            attacker.last_seen = timestamp
        return attacker

    def _get_or_create_session(self, db: Session, cowrie_session_id: str, attacker_id: int, 
                               src_ip: str, src_port: int, dst_ip: str, dst_port: int, timestamp: datetime) -> SessionModel:
        session = db.query(SessionModel).filter(SessionModel.cowrie_session_id == cowrie_session_id).first()
        if not session:
            session = SessionModel(
                cowrie_session_id=cowrie_session_id,
                attacker_id=attacker_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                started_at=timestamp
            )
            db.add(session)
            db.flush()
        return session

    def _process_single_event(self, db: Session, raw_event: Dict[str, Any]) -> Event:
        event_id = raw_event.get("eventid")
        if not event_id:
            return None

        ts_str = raw_event.get("timestamp")
        timestamp = self._parse_timestamp(ts_str) if ts_str else datetime.now(timezone.utc)
        
        src_ip = raw_event.get("src_ip", "127.0.0.1")
        cowrie_session_id = raw_event.get("session")
        
        attacker = self._get_or_create_attacker(db, src_ip, timestamp)
        
        session = None
        if cowrie_session_id:
            src_port = raw_event.get("src_port", 0)
            dst_ip = raw_event.get("dst_ip", "")
            dst_port = raw_event.get("dst_port", 22)
            session = self._get_or_create_session(db, cowrie_session_id, attacker.id, src_ip, src_port, dst_ip, dst_port, timestamp)

        event_uuid = str(uuid.uuid4())
        normalized_type, category, severity, msg = self._normalize_event(raw_event)
        
        db_event = Event(
            event_uuid=event_uuid,
            raw_event_type=event_id,
            normalized_event_type=category,
            timestamp=timestamp,
            attacker_id=attacker.id,
            session_id=session.id if session else None,
            severity=severity,
            message=msg,
            raw_json=raw_event
        )
        db.add(db_event)
        db.flush()

        attacker.total_events += 1
        
        logger.info(f"Processed event: {msg}")

        # Specific Event Handling
        if event_id == "cowrie.session.connect":
            pass
        elif event_id == "cowrie.client.version":
            fp = ClientFingerprint(
                attacker_id=attacker.id,
                session_id=session.id if session else None,
                ssh_version=raw_event.get("version"),
                timestamp=timestamp
            )
            db.add(fp)
        elif event_id == "cowrie.client.kex":
            fp = db.query(ClientFingerprint).filter(ClientFingerprint.session_id == (session.id if session else None)).first()
            if not fp:
                fp = ClientFingerprint(attacker_id=attacker.id, session_id=session.id if session else None, timestamp=timestamp)
                db.add(fp)
            fp.hassh = raw_event.get("hassh")
            fp.kex_algorithms = raw_event.get("kexAlgs")
            fp.encryption_algorithms = raw_event.get("encCS")
            fp.mac_algorithms = raw_event.get("macCS")
            fp.compression_algorithms = raw_event.get("compCS")
        elif event_id in ("cowrie.login.failed", "cowrie.login.success"):
            success = (event_id == "cowrie.login.success")
            auth = AuthenticationAttempt(
                event_id=db_event.id,
                attacker_id=attacker.id,
                session_id=session.id if session else None,
                username=raw_event.get("username"),
                password=raw_event.get("password"),
                result="SUCCESS" if success else "FAILED",
                timestamp=timestamp
            )
            db.add(auth)
            if session:
                if success:
                    session.login_success = True
        elif event_id == "cowrie.command.input":
            cmd = Command(
                event_id=db_event.id,
                session_id=session.id if session else None,
                attacker_id=attacker.id,
                command=raw_event.get("input"),
                category="OTHER",
                severity="LOW",
                timestamp=timestamp
            )
            db.add(cmd)
            if session:
                session.command_count += 1
        elif event_id == "cowrie.log.closed":
            forensic = ForensicLog(
                session_id=session.id if session else None,
                ttylog_path=raw_event.get("ttylog"),
                shasum=raw_event.get("shasum"),
                size=raw_event.get("size"),
                duration=raw_event.get("duration"),
                duplicate=raw_event.get("duplicate"),
                timestamp=timestamp
            )
            db.add(forensic)
        elif event_id == "cowrie.session.closed":
            if session:
                session.ended_at = timestamp
                session.duration = raw_event.get("duration")

        # Run detection engine rules
        self.detection_engine.evaluate_event(db, db_event)
        
        return db_event

    def _normalize_event(self, raw_event: Dict[str, Any]):
        event_id = raw_event.get("eventid")
        if event_id == "cowrie.session.connect":
            return ("CONNECTION", "CONNECTION", "LOW", f"SSH connection established from {raw_event.get('src_ip')}")
        elif event_id == "cowrie.client.version":
            return ("FINGERPRINT", "FINGERPRINT", "LOW", f"SSH client version detected: {raw_event.get('version')}")
        elif event_id == "cowrie.client.kex":
            return ("FINGERPRINT", "FINGERPRINT", "LOW", "SSH key exchange parameters captured")
        elif event_id == "cowrie.login.failed":
            return ("AUTHENTICATION", "AUTHENTICATION", "MEDIUM", f"Login failed for user {raw_event.get('username')}")
        elif event_id == "cowrie.login.success":
            return ("AUTHENTICATION", "AUTHENTICATION", "MEDIUM", f"Login successful for user {raw_event.get('username')}")
        elif event_id == "cowrie.client.size":
            return ("ENVIRONMENT", "ENVIRONMENT", "LOW", "Client terminal size captured")
        elif event_id == "cowrie.client.var":
            return ("ENVIRONMENT", "ENVIRONMENT", "LOW", f"Environment variable {raw_event.get('name')} captured")
        elif event_id == "cowrie.command.input":
            return ("COMMAND", "COMMAND", "LOW", f"Command executed: {raw_event.get('input')}")
        elif event_id == "cowrie.log.closed":
            return ("FORENSICS", "FORENSICS", "LOW", "TTY recording closed")
        elif event_id == "cowrie.session.closed":
            return ("SESSION", "SESSION", "LOW", "Session closed")
        
        return ("OTHER", "OTHER", "LOW", "Unknown event")
