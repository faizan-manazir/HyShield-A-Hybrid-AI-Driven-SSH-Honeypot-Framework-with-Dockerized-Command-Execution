from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database.connection import get_db
from app.models import Event, Attacker, Session as SessionModel, Alert, AuthenticationAttempt, Command

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    total_events = db.query(Event).count()
    active_sessions = db.query(SessionModel).filter(SessionModel.ended_at == None).count()
    unique_attackers = db.query(Attacker).count()
    
    login_failures = db.query(AuthenticationAttempt).filter(AuthenticationAttempt.result == "FAILED").count()
    successful_logins = db.query(AuthenticationAttempt).filter(AuthenticationAttempt.result == "SUCCESS").count()
    
    commands_captured = db.query(Command).count()
    
    open_alerts = db.query(Alert).filter(Alert.status == "OPEN").count()
    high_risk_sessions = db.query(SessionModel).filter(SessionModel.risk_level.in_(["HIGH", "CRITICAL"])).count()
    
    return {
        "total_events": total_events,
        "active_sessions": active_sessions,
        "unique_attackers": unique_attackers,
        "login_failures": login_failures,
        "successful_logins": successful_logins,
        "commands_captured": commands_captured,
        "open_alerts": open_alerts,
        "high_risk_sessions": high_risk_sessions
    }
