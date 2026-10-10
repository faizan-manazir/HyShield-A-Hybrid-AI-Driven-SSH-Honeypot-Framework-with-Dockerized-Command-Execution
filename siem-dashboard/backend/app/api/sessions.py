from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.connection import get_db
from app.models import Session as SessionModel, Event, Command, AuthenticationAttempt, ForensicLog, ClientFingerprint

router = APIRouter(prefix="/api/sessions", tags=["Sessions"])

@router.get("")
def get_sessions(db: Session = Depends(get_db)):
    sessions = db.query(SessionModel).order_by(desc(SessionModel.started_at)).limit(100).all()
    return sessions

@router.get("/{session_id}")
def get_session(session_id: int, db: Session = Depends(get_db)):
    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    events = db.query(Event).filter(Event.session_id == session_id).order_by(Event.timestamp).all()
    commands = db.query(Command).filter(Command.session_id == session_id).all()
    auth = db.query(AuthenticationAttempt).filter(AuthenticationAttempt.session_id == session_id).all()
    forensic = db.query(ForensicLog).filter(ForensicLog.session_id == session_id).first()
    fingerprint = db.query(ClientFingerprint).filter(ClientFingerprint.session_id == session_id).first()
    
    return {
        "session": session,
        "events": events,
        "commands": commands,
        "auth": auth,
        "forensic": forensic,
        "fingerprint": fingerprint
    }
