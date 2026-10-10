from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.connection import get_db
from app.models import Alert, Session as SessionModel, Attacker

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(desc(Alert.created_at)).limit(50).all()
    return alerts

@router.get("/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    session = None
    attacker = None
    
    if alert.session_id:
        session = db.query(SessionModel).filter(SessionModel.id == alert.session_id).first()
        if session and session.attacker_id:
            attacker = db.query(Attacker).filter(Attacker.id == session.attacker_id).first()
            
    return {
        "alert": alert,
        "session": session,
        "attacker": attacker
    }

@router.put("/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    alert.is_resolved = True
    db.commit()
    return {"status": "success", "alert_id": alert_id}
