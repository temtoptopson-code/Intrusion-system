from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from fastapi import FastAPI,Depends,HTTPException,WebSocket,WebSocketDisconnect,Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import select,func
from fastapi.responses import StreamingResponse
import io,csv
from .database import Base,engine,get_db,SessionLocal
from .models import User,TrafficEvent,SecurityAlert,AuditLog
from .security import hash_password,verify_password,token_for,current_user
from .detection import process_event
from .simulator import run_scenario
from .config import CORS_ORIGINS,SENSOR_TOKEN,TIMEZONE,ADMIN_EMAIL,ADMIN_PASSWORD,ADMIN_NAME,JWT_SECRET
from .features import router as features_router
from pydantic import BaseModel,Field
from jose import jwt,JWTError
app=FastAPI(title="Cloud-Based Network Intrusion Detection System",version="1.1.0")
app.include_router(features_router)
app.add_middleware(CORSMiddleware,allow_origins=CORS_ORIGINS,allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
sockets=[]
class LoginIn(BaseModel): email:str; password:str
class EventIn(BaseModel):
    source_ip:str="192.0.2.10"; destination_ip:str="10.0.0.10"
    source_port:int=Field(40000,ge=0,le=65535); destination_port:int=Field(443,ge=0,le=65535)
    protocol:str="TCP"; event_type:str="connection"; bytes_count:int=Field(512,ge=0)
    simulated:bool=False; details:str=""
class AlertUpdate(BaseModel): status:str|None=None; notes:str|None=None
def local(dt):
    if not dt:return None
    if dt.tzinfo is None:dt=dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(ZoneInfo(TIMEZONE)).isoformat()
def ad(a):
    return {"id":a.id,"timestamp":local(a.timestamp),"title":a.title,"attack_type":a.attack_type,"severity":a.severity,"source_ip":a.source_ip,"destination_ip":a.destination_ip,"description":a.description,"recommendation":a.recommendation,"status":a.status,"simulated":a.simulated,"confidence":a.confidence,"notes":a.notes}
async def broadcast(payload):
    gone=[]
    for ws in sockets:
        try: await ws.send_json(payload)
        except Exception: gone.append(ws)
    for ws in gone:
        if ws in sockets:sockets.remove(ws)
@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine); db=SessionLocal()
    try:
        if not db.scalar(select(User).where(User.email==ADMIN_EMAIL)):
            if len(ADMIN_PASSWORD) < 12:
                raise RuntimeError("ADMIN_PASSWORD must contain at least 12 characters.")
            db.add(User(email=ADMIN_EMAIL,full_name=ADMIN_NAME,password_hash=hash_password(ADMIN_PASSWORD),role="Super Administrator"));db.commit()
    finally:db.close()
@app.get("/api/health")
def health():return {"status":"healthy","timezone":TIMEZONE,"server_time":local(datetime.now(timezone.utc))}
@app.post("/api/auth/login")
def login(data:LoginIn,db:Session=Depends(get_db)):
    u=db.scalar(select(User).where(User.email==data.email.lower()))
    if not u or not verify_password(data.password,u.password_hash):raise HTTPException(401,"Incorrect email or password")
    return {"access_token":token_for(u),"token_type":"bearer","user":{"id":u.id,"email":u.email,"full_name":u.full_name,"role":u.role}}
@app.get("/api/auth/me")
def me(u:User=Depends(current_user)):return {"id":u.id,"email":u.email,"full_name":u.full_name,"role":u.role}
@app.get("/api/dashboard")
def dashboard(db:Session=Depends(get_db),u:User=Depends(current_user)):
    count=lambda q:db.scalar(q) or 0
    metrics={"events":count(select(func.count(TrafficEvent.id))),"alerts":count(select(func.count(SecurityAlert.id))),"open_alerts":count(select(func.count(SecurityAlert.id)).where(SecurityAlert.status!="Resolved")),"critical":count(select(func.count(SecurityAlert.id)).where(SecurityAlert.severity=="Critical",SecurityAlert.status!="Resolved")),"sensors_online":0}
    sev={s:count(select(func.count(SecurityAlert.id)).where(SecurityAlert.severity==s)) for s in ["Critical","High","Medium","Low"]}
    recent=db.scalars(select(SecurityAlert).order_by(SecurityAlert.timestamp.desc()).limit(6)).all()
    return {"metrics":metrics,"severity":sev,"recent_alerts":[ad(a) for a in recent],"timezone":TIMEZONE,"mode":"Simulation-ready / Live sensor optional"}
@app.get("/api/alerts")
def alerts(limit:int=100,severity:str|None=None,status:str|None=None,db:Session=Depends(get_db),u:User=Depends(current_user)):
    q=select(SecurityAlert).order_by(SecurityAlert.timestamp.desc()).limit(min(max(limit,1),500))
    if severity:q=q.where(SecurityAlert.severity==severity)
    if status:q=q.where(SecurityAlert.status==status)
    return [ad(a) for a in db.scalars(q).all()]
@app.patch("/api/alerts/{aid}")
def update(aid:int,data:AlertUpdate,db:Session=Depends(get_db),u:User=Depends(current_user)):
    a=db.get(SecurityAlert,aid)
    if not a:raise HTTPException(404,"Alert not found")
    if data.status:
        if data.status not in ["New","Acknowledged","Investigating","Resolved"]:raise HTTPException(400,"Invalid status")
        a.status=data.status
    if data.notes is not None:a.notes=data.notes
    db.add(AuditLog(actor=u.email,action="alert_updated",detail=f"Alert {aid} updated"));db.commit();db.refresh(a);return ad(a)
@app.get("/api/traffic")
def traffic(limit:int=100,db:Session=Depends(get_db),u:User=Depends(current_user)):
    es=db.scalars(select(TrafficEvent).order_by(TrafficEvent.timestamp.desc()).limit(min(max(limit,1),500))).all()
    return [{"id":e.id,"timestamp":local(e.timestamp),"source_ip":e.source_ip,"destination_ip":e.destination_ip,"source_port":e.source_port,"destination_port":e.destination_port,"protocol":e.protocol,"event_type":e.event_type,"bytes_count":e.bytes_count,"simulated":e.simulated} for e in es]
@app.get("/api/analytics")
def analytics(db:Session=Depends(get_db),u:User=Depends(current_user)):
    rows=db.execute(select(SecurityAlert.attack_type,func.count(SecurityAlert.id)).group_by(SecurityAlert.attack_type)).all()
    sev=db.execute(select(SecurityAlert.severity,func.count(SecurityAlert.id)).group_by(SecurityAlert.severity)).all()
    return {"attack_types":[{"name":n,"value":c} for n,c in rows],"severity":[{"name":n,"value":c} for n,c in sev],"recent_traffic":db.scalar(select(func.count(TrafficEvent.id))) or 0}
@app.post("/api/simulation/{scenario}")
async def simulate(scenario:str,db:Session=Depends(get_db),u:User=Depends(current_user)):
    try:r=run_scenario(db,scenario)
    except ValueError as e:raise HTTPException(400,str(e))
    await broadcast({"type":"simulation","data":r})
    for aid in r["alerts_created"]:
        a=db.get(SecurityAlert,aid)
        if a:await broadcast({"type":"alert","data":ad(a)})
    return r
@app.post("/api/sensor/events")
async def sensor_event(event:EventIn,x_sensor_token:str|None=Header(default=None),db:Session=Depends(get_db)):
    if not x_sensor_token or x_sensor_token!=SENSOR_TOKEN:raise HTTPException(401,"Invalid sensor token")
    data=event.model_dump();data["simulated"]=False
    e,als=process_event(db,data)
    for a in als:await broadcast({"type":"alert","data":ad(a)})
    return {"event_id":e.id,"alerts_created":[a.id for a in als],"simulated":False}
@app.get("/api/reports/alerts.csv")
def csv_report(db:Session=Depends(get_db),u:User=Depends(current_user)):
    out=io.StringIO();w=csv.writer(out);w.writerow(["ID","Timestamp Africa/Lagos","Attack type","Severity","Source IP","Destination IP","Status","Simulated"])
    for a in db.scalars(select(SecurityAlert).order_by(SecurityAlert.timestamp.desc())).all():w.writerow([a.id,local(a.timestamp),a.attack_type,a.severity,a.source_ip,a.destination_ip,a.status,a.simulated])
    out.seek(0);return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=nids-alert-report.csv"})
@app.websocket("/ws/events")
async def ws_events(ws:WebSocket):
    await ws.accept()
    db=SessionLocal()
    try:
        token=await ws.receive_text()
        try:
            payload=jwt.decode(token,JWT_SECRET,algorithms=["HS256"]);uid=int(payload["sub"])
            if not db.get(User,uid):raise ValueError("unknown user")
        except (JWTError,ValueError,KeyError,TypeError):
            await ws.close(code=1008);return
        sockets.append(ws)
        while True:await ws.receive_text()
    except WebSocketDisconnect:pass
    finally:
        if ws in sockets:sockets.remove(ws)
        db.close()
