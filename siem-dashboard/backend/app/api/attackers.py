from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.connection import get_db
from app.models import Attacker, Session as SessionModel, Event, Command, AuthenticationAttempt

router = APIRouter(prefix="/api/attackers", tags=["Attackers"])

@router.get("")
def get_attackers(db: Session = Depends(get_db)):
    return db.query(Attacker).order_by(desc(Attacker.last_seen)).limit(50).all()

@router.get("/top")
def get_top_attackers(db: Session = Depends(get_db)):
    return db.query(Attacker).order_by(desc(Attacker.threat_score)).limit(5).all()

@router.get("/{attacker_id}")
def get_attacker(attacker_id: int, db: Session = Depends(get_db)):
    attacker = db.query(Attacker).filter(Attacker.id == attacker_id).first()
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
        
    sessions = db.query(SessionModel).filter(SessionModel.attacker_id == attacker_id).all()
    events = db.query(Event).filter(Event.attacker_id == attacker_id).order_by(desc(Event.timestamp)).limit(50).all()
    commands = db.query(Command).filter(Command.attacker_id == attacker_id).limit(100).all()
    auth_attempts = db.query(AuthenticationAttempt).filter(AuthenticationAttempt.attacker_id == attacker_id).all()
    
    return {
        "attacker": attacker,
        "sessions": sessions,
        "recent_events": events,
        "commands": commands,
        "auth": auth_attempts
    }
