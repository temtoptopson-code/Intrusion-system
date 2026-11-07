from datetime import datetime,timedelta,timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import TrafficEvent,SecurityAlert
from .features import DetectionRule,IPRule,notify_security_alert

def process_event(db:Session,data:dict):
    event=TrafficEvent(**data); db.add(event); db.flush(); alerts=[]
    cutoff=datetime.now(timezone.utc)-timedelta(seconds=60)
    recent=db.scalars(select(TrafficEvent).where(TrafficEvent.source_ip==event.source_ip,TrafficEvent.timestamp>=cutoff)).all()
    defaults={"port_scan":12,"brute_force":5,"syn_flood":30}
    configured={x.rule_key:x for x in db.scalars(select(DetectionRule)).all()}
    def threshold(key):
        row=configured.get(key)
        return row.threshold if row else defaults[key]
    def enabled(key):
        row=configured.get(key)
        return row.enabled if row else True
    def add(title,kind,severity,desc,reco,confidence):
        a=SecurityAlert(title=title,attack_type=kind,severity=severity,source_ip=event.source_ip,destination_ip=event.destination_ip,description=desc,recommendation=reco,simulated=event.simulated,confidence=confidence)
        db.add(a); alerts.append(a)
    ip_rule=db.scalar(select(IPRule).where(IPRule.ip_address==event.source_ip,IPRule.list_type=="blacklist"))
    if ip_rule:
        add("Traffic from blacklisted IP","Blacklisted Source","High",f"Traffic was received from an IP address on the local blacklist. Rule reason: {ip_rule.reason or 'No reason supplied'}.","Investigate the source and apply an appropriate control at your authorized firewall or network gateway.",.95)
    if enabled("port_scan") and event.event_type=="connection" and len({x.destination_port for x in recent})>=threshold("port_scan"):
        add("Possible port scan detected","Port Scan","High",f"At least {threshold('port_scan')} unique destination ports were contacted by this source within approximately one minute.","Inspect connection logs and confirm whether the source is an authorized scanner.",.89)
    if enabled("brute_force") and event.event_type=="auth_failure":
        failures=db.scalars(select(TrafficEvent).where(TrafficEvent.source_ip==event.source_ip,TrafficEvent.event_type=="auth_failure",TrafficEvent.timestamp>=datetime.now(timezone.utc)-timedelta(minutes=5))).all()
        if len(failures)>=threshold("brute_force"): add("Repeated authentication failures","Brute Force","High",f"At least {threshold('brute_force')} authentication failure events were observed from one source within five minutes.","Review service authentication logs and apply account protection or rate limiting.",.92)
    if enabled("syn_flood") and event.event_type=="syn":
        syns=db.scalars(select(TrafficEvent).where(TrafficEvent.source_ip==event.source_ip,TrafficEvent.event_type=="syn",TrafficEvent.timestamp>=datetime.now(timezone.utc)-timedelta(seconds=10))).all()
        if len(syns)>=threshold("syn_flood"): add("High-rate SYN activity","SYN Flood Indicator","Critical",f"A high rate of at least {threshold('syn_flood')} SYN packet metadata events was observed. This heuristic is not proof of DDoS.","Correlate with firewall and flow telemetry before mitigation.",.86)
    if event.event_type=="dns_suspicious":
        add("Suspicious DNS activity","Suspicious DNS","Medium","An unusual DNS query pattern was flagged by the sensor or simulator.","Review queried domains and resolver logs; correlate endpoint telemetry.",.78)
    if event.bytes_count>5000000:
        add("Unusually large traffic event","Traffic Anomaly","Medium","One event reported unusually high byte volume.","Compare with baseline and inspect the associated flow.",.70)
    db.commit(); db.refresh(event)
    for a in alerts:
        db.refresh(a)
        notify_security_alert(a, db)
    return event,alerts
