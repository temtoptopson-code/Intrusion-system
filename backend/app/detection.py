from datetime import datetime,timedelta,timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import TrafficEvent,SecurityAlert
def process_event(db:Session,data:dict):
    event=TrafficEvent(**data); db.add(event); db.flush(); alerts=[]
    cutoff=datetime.now(timezone.utc)-timedelta(seconds=60)
    recent=db.scalars(select(TrafficEvent).where(TrafficEvent.source_ip==event.source_ip,TrafficEvent.timestamp>=cutoff)).all()
    def add(title,kind,severity,desc,reco,confidence):
        a=SecurityAlert(title=title,attack_type=kind,severity=severity,source_ip=event.source_ip,destination_ip=event.destination_ip,description=desc,recommendation=reco,simulated=event.simulated,confidence=confidence)
        db.add(a); alerts.append(a)
    if event.event_type=="connection" and len({x.destination_port for x in recent})>=12:
        add("Possible port scan detected","Port Scan","High","At least 12 unique destination ports were contacted by this source within approximately one minute.","Inspect connection logs and confirm whether the source is an authorized scanner.",.89)
    if event.event_type=="auth_failure":
        failures=db.scalars(select(TrafficEvent).where(TrafficEvent.source_ip==event.source_ip,TrafficEvent.event_type=="auth_failure",TrafficEvent.timestamp>=datetime.now(timezone.utc)-timedelta(minutes=5))).all()
        if len(failures)>=5: add("Repeated authentication failures","Brute Force","High","Multiple authentication failure events were observed from one source within five minutes.","Review service authentication logs and apply account protection or rate limiting.",.92)
    if event.event_type=="syn":
        syns=db.scalars(select(TrafficEvent).where(TrafficEvent.source_ip==event.source_ip,TrafficEvent.event_type=="syn",TrafficEvent.timestamp>=datetime.now(timezone.utc)-timedelta(seconds=10))).all()
        if len(syns)>=30: add("High-rate SYN activity","SYN Flood Indicator","Critical","A high rate of SYN packet metadata was observed. This heuristic is not proof of DDoS.","Correlate with firewall and flow telemetry before mitigation.",.86)
    if event.event_type=="dns_suspicious":
        add("Suspicious DNS activity","Suspicious DNS","Medium","An unusual DNS query pattern was flagged by the sensor or simulator.","Review queried domains and resolver logs; correlate endpoint telemetry.",.78)
    if event.bytes_count>5000000:
        add("Unusually large traffic event","Traffic Anomaly","Medium","One event reported unusually high byte volume.","Compare with baseline and inspect the associated flow.",.70)
    db.commit(); db.refresh(event)
    for a in alerts: db.refresh(a)
    return event,alerts
