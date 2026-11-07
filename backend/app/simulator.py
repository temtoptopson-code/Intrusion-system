import random
from .detection import process_event
SCENARIOS={"port_scan":("connection",20),"brute_force":("auth_failure",8),"syn_flood":("syn",35),"dns":("dns_suspicious",1),"normal":("connection",1)}
SOURCES={"port_scan":"198.51.100.23","brute_force":"203.0.113.44","syn_flood":"192.0.2.77","dns":"203.0.113.88","normal":"10.10.2.15"}
def run_scenario(db,scenario):
    if scenario not in SCENARIOS: raise ValueError("Unknown simulation scenario")
    kind,count=SCENARIOS[scenario]; ids=[]; alert_ids=[]
    for i in range(count):
        event,alerts=process_event(db,{"source_ip":SOURCES[scenario],"destination_ip":"10.0.0.10","source_port":random.randint(20000,65000),"destination_port":random.randint(1,1024) if scenario=="port_scan" else (53 if scenario=="dns" else 443),"protocol":"UDP" if scenario=="dns" else "TCP","event_type":kind,"bytes_count":random.randint(80,1400),"simulated":True,"details":scenario+" demonstration event"})
        ids.append(event.id); alert_ids.extend(a.id for a in alerts)
    return {"scenario":scenario,"events_created":len(ids),"event_ids":ids,"alerts_created":alert_ids}
