import logging
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from app.models import Event, Attacker, Alert, Session as SessionModel, Command, AuthenticationAttempt

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self, websocket_manager=None, loop=None):
        self.ws_manager = websocket_manager
        self.loop = loop

    def evaluate_event(self, db: Session, event: Event):
        # 1. Sensitive File Access
        if event.normalized_event_type == "COMMAND":
            self._check_sensitive_file_access(db, event)
            
        # 2. Authentication Rules
        if event.normalized_event_type == "AUTHENTICATION":
            self._check_repeated_login_failures(db, event)

    def _create_alert(self, db: Session, title: str, code: str, description: str, severity: str, score: float, event: Event):
        # Check if alert already recently generated for this session/attacker
        existing = db.query(Alert).filter(
            Alert.alert_code == code,
            Alert.session_id == event.session_id
        ).first()
        
        if existing:
            return
            
        alert = Alert(
            alert_code=code,
            title=title,
            description=description,
            severity=severity,
            threat_score=score,
            attacker_id=event.attacker_id,
            session_id=event.session_id,
            event_id=event.id
        )
        db.add(alert)
        
        # Update Attacker Threat Score
        attacker = db.query(Attacker).filter(Attacker.id == event.attacker_id).first()
        if attacker:
            if attacker.threat_score is None:
                attacker.threat_score = 0.0
            attacker.threat_score += score
            
        db.flush()
        
        logger.warning(f"ALERT GENERATED: {title} (Severity: {severity})")
        
        # Broadcast alert
        if self.ws_manager and getattr(self, 'loop', None):
            import asyncio
            msg = {
                "type": "new_alert",
                "data": {
                    "id": alert.id,
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            }
            asyncio.run_coroutine_threadsafe(self.ws_manager.broadcast(msg), self.loop)

    def _check_sensitive_file_access(self, db: Session, event: Event):
        cmd = db.query(Command).filter(Command.event_id == event.id).first()
        if cmd:
            suspicious = ["/etc/passwd", "/etc/shadow", "authorized_keys", ".ssh"]
            if any(s in cmd.command for s in suspicious):
                self._create_alert(
                    db,
                    title="Sensitive File Access",
                    code="SENSITIVE_FILE",
                    description=f"Command executed targeting sensitive file: {cmd.command}",
                    severity="HIGH",
                    score=20.0,
                    event=event
                )

    def _check_repeated_login_failures(self, db: Session, event: Event):
        # Check if 5 failures in last 60 seconds
        time_threshold = event.timestamp - timedelta(seconds=60)
        failures = db.query(AuthenticationAttempt).filter(
            AuthenticationAttempt.attacker_id == event.attacker_id,
            AuthenticationAttempt.result == "FAILED",
            AuthenticationAttempt.timestamp >= time_threshold
        ).count()
        
        if failures >= 5:
            self._create_alert(
                db,
                title="Repeated Login Failures",
                code="BRUTE_FORCE",
                description="5 or more failed logins from the same source IP within 60 seconds",
                severity="HIGH",
                score=15.0,
                event=event
            )
