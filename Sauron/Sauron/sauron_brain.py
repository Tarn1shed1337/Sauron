from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime , Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import func
import datetime
import logging
import requests

DB_URL = "postgresql://sauron_admin:swampizzo@sauron-db/threat_intel"
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False,autoflush =False,bind=engine)
Base = declarative_base()
class AttackEntry(Base):
    __tablename__ = "attacks"
    id = Column(Integer,primary_key = True , index = True)
    agent_id = Column(String)
    attacker_id = Column(String)
    service = Column(String)
    timestamp = Column(DateTime, default = datetime.datetime.utcnow )
    country = Column(String, default="Unknown")
    city = Column(String, default="Unknown")
    latitude = Column(Float, default=0.0)
    longitude = Column(Float, default=0.0)

Base.metadata.create_all(bind=engine)

app = FastAPI()
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
class AttackReport(BaseModel):
    agent_id : str
    attacker_id : str
    service : str

logger = logging.getLogger("sauron.brain")
def get_geo_data(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}",timeout = 5).json()
        if response.get("status") == "success":
            return{
                "country" : response.get("country"),
                "city": response.get("city"),
                "lat": response.get("lat"),
                "lon":response.get("lon")
            }
    except Exception:
        pass
    return {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0}

def analyze_threat(db: Session, attacker_ip: str):
    attack_count = db.query(AttackEntry).filter(AttackEntry.attacker_id == attacker_ip).count()
    if attack_count >= 5:
        logger.critical(f"CRITICAL: {attacker_ip} is a persistent threat ({attack_count} attempts)!")
        return "CRITICAL"
    elif attack_count >= 2:
        logger.warning(f"WARNING: {attacker_ip} has multiple attempts ({attack_count}). Monitor closely.")
        return "WARNING"
    return "MONITORING"
@app.get("/")
async def root():
    return {"message": "Sauron Nexus is Online"}

@app.post("/report")
async def receive_report(report: AttackReport , db: Session = Depends(get_db)):
    new_attack = AttackEntry(
        agent_id = report.agent_id,
        attacker_id = report.attacker_id,
        service = report.service,
        country=geo["country"],
        city=geo["city"],
        latitude= geo["lat"],
        longitude=geo["lon"]
    )
    db.add(new_attack)
    db.commit()
    threat_level = analyze_threat(db, report.attacker_id)
    return {
        "status": "recorded",
        "threat_level": threat_level,
        "total_attempts": db.query(AttackEntry).filter(AttackEntry.attacker_id == report.attacker_id).count()
    }

@app.get("/banlist")
async def get_banlist(db: Session = Depends(get_db)):
    results = db.query(
        AttackEntry.attacker_id, 
        func.count(AttackEntry.id)
    ).group_by(AttackEntry.attacker_id).all()
    ips = [ip for ip, count in results if count >= 5 and ip != "0.0.0.0"]   
    return {"banned_ips": ips}

@app.delete("/pardon/{ip}")
async def pardon_ip(ip: str, db: Session = Depends(get_db)):
    num_deleted = db.query(AttackEntry).filter(AttackEntry.attacker_id == ip).delete()
    db.commit()
    if num_deleted > 0:
        return {"message": f"IP {ip} has been pardoned. {num_deleted} records wiped."}
    return {"message": "IP not found in records."}


