from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database.connection import get_db
from app.models import Event, Attacker, Session as SessionModel, Alert, AuthenticationAttempt, Command
from datetime import datetime, timedelta, timezone

router = APIRouter(prefix="/api/charts", tags=["Charts"])

@router.get("/events-over-time")
def get_events_over_time(db: Session = Depends(get_db)):
    # Group by day for all events
    events = db.query(Event.timestamp).all()
    
    # Group by day/hour
    data = {}
    for ev in events:
        day_str = ev.timestamp.strftime("%Y-%m-%d")
        data[day_str] = data.get(day_str, 0) + 1
        
    formatted = [{"date": k, "count": v} for k, v in sorted(data.items())]
    return formatted

@router.get("/event-distribution")
def get_event_distribution(db: Session = Depends(get_db)):
    results = db.query(Event.normalized_event_type, func.count(Event.id)).group_by(Event.normalized_event_type).all()
    return [{"category": r[0], "count": r[1]} for r in results]
