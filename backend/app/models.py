from datetime import datetime,timezone
from sqlalchemy import String,Integer,Float,Boolean,DateTime,Text,Index
from sqlalchemy.orm import Mapped,mapped_column
from .database import Base
def utcnow(): return datetime.now(timezone.utc)
class User(Base):
    __tablename__="users"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    email:Mapped[str]=mapped_column(String(255),unique=True,index=True)
    full_name:Mapped[str]=mapped_column(String(120),default="Administrator")
    password_hash:Mapped[str]=mapped_column(String(255))
    role:Mapped[str]=mapped_column(String(40),default="Security Administrator")
class TrafficEvent(Base):
    __tablename__="traffic_events"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    timestamp:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow,index=True)
    source_ip:Mapped[str]=mapped_column(String(64),index=True)
    destination_ip:Mapped[str]=mapped_column(String(64),default="10.0.0.10")
    source_port:Mapped[int]=mapped_column(Integer,default=0)
    destination_port:Mapped[int]=mapped_column(Integer,default=0)
    protocol:Mapped[str]=mapped_column(String(20),default="TCP")
    event_type:Mapped[str]=mapped_column(String(60),default="connection")
    bytes_count:Mapped[int]=mapped_column(Integer,default=0)
    simulated:Mapped[bool]=mapped_column(Boolean,default=True)
    details:Mapped[str]=mapped_column(Text,default="")
class SecurityAlert(Base):
    __tablename__="security_alerts"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    timestamp:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow,index=True)
    title:Mapped[str]=mapped_column(String(180))
    attack_type:Mapped[str]=mapped_column(String(80),index=True)
    severity:Mapped[str]=mapped_column(String(20),index=True)
    source_ip:Mapped[str]=mapped_column(String(64),index=True)
    destination_ip:Mapped[str]=mapped_column(String(64),default="Unknown")
    description:Mapped[str]=mapped_column(Text)
    recommendation:Mapped[str]=mapped_column(Text)
    status:Mapped[str]=mapped_column(String(30),default="New",index=True)
    simulated:Mapped[bool]=mapped_column(Boolean,default=True)
    confidence:Mapped[float]=mapped_column(Float,default=0.0)
    notes:Mapped[str]=mapped_column(Text,default="")
class AuditLog(Base):
    __tablename__="audit_logs"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    timestamp:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow)
    actor:Mapped[str]=mapped_column(String(255))
    action:Mapped[str]=mapped_column(String(120))
    detail:Mapped[str]=mapped_column(Text,default="")
Index("ix_traffic_source_time",TrafficEvent.source_ip,TrafficEvent.timestamp)
