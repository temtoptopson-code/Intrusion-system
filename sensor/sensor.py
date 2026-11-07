import os, requests
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
API=os.getenv("NIDS_API_URL","http://localhost:8000")
TOKEN=os.getenv("NIDS_SENSOR_TOKEN","local-demo-sensor-token")
INTERFACE=os.getenv("NIDS_INTERFACE")
def submit(pkt):
    if IP not in pkt:return
    proto="TCP" if TCP in pkt else "UDP" if UDP in pkt else "IP"
    sport=int(pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else 0)
    dport=int(pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0)
    etype="dns_suspicious" if DNS in pkt and DNSQR in pkt else "syn" if TCP in pkt and int(pkt[TCP].flags)&0x02 else "connection"
    payload={"source_ip":pkt[IP].src,"destination_ip":pkt[IP].dst,"source_port":sport,"destination_port":dport,"protocol":proto,"event_type":etype,"bytes_count":len(pkt),"simulated":False,"details":"Packet metadata captured by authorized Scapy sensor"}
    try:
        r=requests.post(API+"/api/sensor/events",json=payload,headers={"X-Sensor-Token":TOKEN},timeout=5);r.raise_for_status()
    except requests.RequestException as exc:print("Ingestion error:",exc)
if __name__=="__main__":
    print("NIDS sensor starting; capture only on an authorized interface.")
    sniff(iface=INTERFACE,prn=submit,store=False)
