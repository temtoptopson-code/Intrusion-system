from datetime import datetime, timezone
from io import BytesIO
import os, json
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import String, Integer, DateTime, Text, Boolean, select, func
from sqlalchemy.orm import Session, Mapped, mapped_column
from .database import Base, get_db
from .models import User, SecurityAlert, TrafficEvent, AuditLog
from .security import current_user, hash_password

router = APIRouter(prefix="/api", tags=["security administration"])

class IPRule(Base):
    __tablename__ = "ip_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    list_type: Mapped[str] = mapped_column(String(12), default="watch")
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_key: Mapped[str] = mapped_column(String(60), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(120))
    threshold: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default="")

class UserIn(BaseModel):
    email: str
    full_name: str = "NIDS User"
    password: str = Field(min_length=12)
    role: str = "Security Analyst"

class IPIn(BaseModel):
    ip_address: str
    list_type: str = "watch"
    reason: str = ""

class RuleIn(BaseModel):
    threshold: int = Field(ge=1, le=100000)
    enabled: bool = True

def admin(user: User):
    if user.role not in ("Super Administrator", "Super Admin"):
        raise HTTPException(403, "Super Administrator permission required")

def audit(db, user, action, detail):
    db.add(AuditLog(actor=user.email, action=action, detail=detail))
    db.commit()

@router.get("/admin/ip-rules")
def list_ip_rules(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [dict(id=x.id, ip_address=x.ip_address, list_type=x.list_type, reason=x.reason, created_by=x.created_by, created_at=x.created_at.isoformat()) for x in db.scalars(select(IPRule).order_by(IPRule.created_at.desc())).all()]

@router.post("/admin/ip-rules")
def add_ip_rule(data: IPIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    admin(user)
    import ipaddress
    try: ipaddress.ip_address(data.ip_address)
    except ValueError: raise HTTPException(400, "Enter a valid IPv4 or IPv6 address")
    if data.list_type not in ("watch", "blacklist", "whitelist"): raise HTTPException(400, "Invalid list type")
    existing = db.scalar(select(IPRule).where(IPRule.ip_address == data.ip_address))
    if existing: raise HTTPException(409, "This IP address already exists")
    row = IPRule(ip_address=data.ip_address, list_type=data.list_type, reason=data.reason, created_by=user.email)
    db.add(row); db.flush(); db.add(AuditLog(actor=user.email, action="ip_rule_added", detail=f"{data.list_type}: {data.ip_address}")); db.commit(); db.refresh(row)
    return {"id": row.id, "ip_address": row.ip_address, "list_type": row.list_type, "reason": row.reason}

@router.delete("/admin/ip-rules/{rule_id}")
def delete_ip_rule(rule_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    admin(user)
    row = db.get(IPRule, rule_id)
    if not row: raise HTTPException(404, "IP rule not found")
    db.delete(row); db.add(AuditLog(actor=user.email, action="ip_rule_removed", detail=row.ip_address)); db.commit()
    return {"deleted": True}

@router.get("/admin/detection-rules")
def list_rules(db: Session = Depends(get_db), user: User = Depends(current_user)):
    defaults = [("port_scan", "Port scan", 12, "Unique destination ports within approximately one minute"), ("brute_force", "Brute-force", 5, "Authentication failures within five minutes"), ("syn_flood", "SYN flood indicator", 30, "SYN metadata events within ten seconds")]
    for key, label, threshold, desc in defaults:
        if not db.scalar(select(DetectionRule).where(DetectionRule.rule_key == key)):
            db.add(DetectionRule(rule_key=key, label=label, threshold=threshold, enabled=True, description=desc))
    db.commit()
    return [dict(rule_key=x.rule_key, label=x.label, threshold=x.threshold, enabled=x.enabled, description=x.description) for x in db.scalars(select(DetectionRule).order_by(DetectionRule.id)).all()]

@router.put("/admin/detection-rules/{rule_key}")
def update_rule(rule_key: str, data: RuleIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    admin(user)
    row = db.scalar(select(DetectionRule).where(DetectionRule.rule_key == rule_key))
    if not row: raise HTTPException(404, "Detection rule not found")
    row.threshold = data.threshold; row.enabled = data.enabled
    db.add(AuditLog(actor=user.email, action="detection_rule_updated", detail=f"{rule_key}: threshold={data.threshold}, enabled={data.enabled}")); db.commit()
    return {"rule_key": row.rule_key, "threshold": row.threshold, "enabled": row.enabled}

@router.get("/admin/users")
def list_users(db: Session = Depends(get_db), user: User = Depends(current_user)):
    admin(user)
    return [dict(id=x.id, email=x.email, full_name=x.full_name, role=x.role) for x in db.scalars(select(User).order_by(User.id)).all()]

@router.post("/admin/users")
def create_user(data: UserIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    admin(user)
    email = data.email.strip().lower()
    if db.scalar(select(User).where(User.email == email)): raise HTTPException(409, "Email already exists")
    if data.role not in ("Super Administrator", "Security Analyst", "Viewer"): raise HTTPException(400, "Invalid role")
    row = User(email=email, full_name=data.full_name, password_hash=hash_password(data.password), role=data.role)
    db.add(row); db.add(AuditLog(actor=user.email, action="user_created", detail=f"{email} ({data.role})")); db.commit(); db.refresh(row)
    return {"id": row.id, "email": row.email, "full_name": row.full_name, "role": row.role}

@router.delete("/admin/users/{user_id}")
def remove_user(user_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    admin(user)
    if user_id == user.id: raise HTTPException(400, "You cannot delete your own account")
    row = db.get(User, user_id)
    if not row: raise HTTPException(404, "User not found")
    db.delete(row); db.add(AuditLog(actor=user.email, action="user_deleted", detail=row.email)); db.commit()
    return {"deleted": True}

@router.get("/admin/audit")
def audit_logs(limit: int = 200, db: Session = Depends(get_db), user: User = Depends(current_user)):
    admin(user)
    rows = db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(min(max(limit, 1), 500))).all()
    return [dict(id=x.id, timestamp=x.timestamp.isoformat(), actor=x.actor, action=x.action, detail=x.detail) for x in rows]

def _send_resend_email(recipients, subject, text):
    api_key = os.getenv("RESEND_API_KEY")
    sender = os.getenv("RESEND_FROM")
    if not api_key or not sender:
        raise RuntimeError("Resend is not configured")
    payload = json.dumps({
        "from": sender,
        "to": recipients,
        "subject": subject,
        "text": text,
    }).encode("utf-8")
    request = Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "NIDS-Backend/1.0",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))
        return result
    except HTTPError as exc:
        raw_body = exc.read().decode("utf-8", errors="replace")
        try:
            error_data = json.loads(raw_body)
            reason = error_data.get("message") or error_data.get("name") or raw_body[:300]
        except Exception:
            reason = raw_body[:300] or "Empty error response"
        raise RuntimeError(f"Resend API returned HTTP {exc.code}: {reason}") from exc


@router.post("/notifications/test")
def test_email(user: User = Depends(current_user)):
    if not os.getenv("RESEND_API_KEY") or not os.getenv("RESEND_FROM"):
        raise HTTPException(503, "Email is not configured. Set RESEND_API_KEY and RESEND_FROM in Render.")
    try:
        _send_resend_email(
            [user.email],
            "NIDS notification test",
            "Your Network Intrusion Detection System email notification settings are working.",
        )
    except RuntimeError as exc:
        raise HTTPException(502, f"Email delivery failed: {str(exc)}")
    except Exception as exc:
        raise HTTPException(502, f"Email delivery failed: {type(exc).__name__}")
    return {"sent": True, "recipient": user.email}

@router.get("/reports/alerts.pdf")
def pdf_report(db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError: raise HTTPException(503, "PDF reporting dependency is not installed yet")
    alerts=db.scalars(select(SecurityAlert).order_by(SecurityAlert.timestamp.desc()).limit(1000)).all()
    buf=BytesIO(); doc=SimpleDocTemplate(buf,pagesize=landscape(A4)); styles=getSampleStyleSheet()
    story=[Paragraph("Network Intrusion Detection — Security Report",styles["Title"]),Paragraph(f"Generated {datetime.now(timezone.utc).isoformat()} · User: {user.email}",styles["Normal"]),Spacer(1,14)]
    data=[["ID","Time (UTC)","Attack","Severity","Source IP","Status","Mode"]]
    data += [[str(a.id),a.timestamp.strftime("%Y-%m-%d %H:%M") if a.timestamp else "",a.attack_type,a.severity,a.source_ip,a.status,"Simulated" if a.simulated else "Sensor"] for a in alerts]
    table=Table(data,repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#15334d")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.3,colors.lightgrey),("FONTSIZE",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#edf3f8")])]))
    story.append(table); doc.build(story); buf.seek(0)
    return StreamingResponse(buf,media_type="application/pdf",headers={"Content-Disposition":"attachment; filename=nids-security-report.pdf"})

@router.get("/analytics/extended")
def extended_analytics(db: Session = Depends(get_db), user: User = Depends(current_user)):
    attacks=db.execute(select(SecurityAlert.attack_type,func.count(SecurityAlert.id)).group_by(SecurityAlert.attack_type)).all()
    sources=db.execute(select(SecurityAlert.source_ip,func.count(SecurityAlert.id)).group_by(SecurityAlert.source_ip).order_by(func.count(SecurityAlert.id).desc()).limit(10)).all()
    ports=db.execute(select(TrafficEvent.destination_port,func.count(TrafficEvent.id)).group_by(TrafficEvent.destination_port).order_by(func.count(TrafficEvent.id).desc()).limit(10)).all()
    return {"attack_types":[{"name":x,"count":n} for x,n in attacks],"top_sources":[{"ip":x,"alerts":n} for x,n in sources],"top_ports":[{"port":x,"events":n} for x,n in ports]}

def notify_security_alert(alert):
    recipients = [item.strip() for item in os.getenv("ALERT_RECIPIENTS", "").split(",") if item.strip()]
    if not recipients or alert.severity not in ("Critical", "High"):
        return
    try:
        _send_resend_email(
            recipients,
            f"NIDS {alert.severity} alert: {alert.attack_type}",
            f"{alert.title}\nSeverity: {alert.severity}\nSource IP: {alert.source_ip}\nDestination IP: {alert.destination_ip}\nDetails: {alert.description}\nAutomated heuristic detection notification.",
        )
    except Exception:
        return  # Email failure must never interrupt alert persistence.