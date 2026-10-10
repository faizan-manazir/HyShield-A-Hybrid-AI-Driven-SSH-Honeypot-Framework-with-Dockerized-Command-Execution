from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.connection import get_db
from app.models import Event, Attacker, Session as SessionModel

router = APIRouter(prefix="/api/events", tags=["Events"])

@router.get("")
def get_events(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    events = db.query(Event).order_by(desc(Event.timestamp)).limit(limit).offset(offset).all()
    # Simple dict mapping since no schemas yet
    return [
        {
            "id": ev.id,
            "timestamp": ev.timestamp,
            "event_type": ev.normalized_event_type,
            "raw_event_type": ev.raw_event_type,
            "severity": ev.severity,
            "message": ev.message,
            "session_id": ev.session_id,
            "attacker_id": ev.attacker_id
        } for ev in events
    ]
