import math
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from database import init_db, get_db, Responder, Incident, User, TrustedContact, UnsafeArea, SafetyAudit
from rag import safety_rag
from auth import hash_password, verify_password, create_token, get_current_user, decode_token

app = FastAPI(title="StreeSafe API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()
    seed_responders()


def seed_responders():
    from database import SessionLocal

    db = SessionLocal()
    if db.query(Responder).count() == 0:
        demo_responders = [
            Responder(name="Aarav (Volunteer)", phone="+91-90000-00001", lat=26.9124, lng=75.7873, is_available="true"),
            Responder(name="Priya (Trusted contact)", phone="+91-90000-00002", lat=26.9260, lng=75.8010, is_available="true"),
            Responder(name="Rohan (Volunteer)", phone="+91-90000-00003", lat=26.8990, lng=75.7700, is_available="true"),
            Responder(name="Nikhil (Volunteer)", phone="+91-90000-00004", lat=26.9350, lng=75.7600, is_available="true"),
        ]
        db.add_all(demo_responders)
        db.commit()
    db.close()


def haversine_km(lat1, lng1, lat2, lng2):
    R = 6371
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lng2 - lng1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def get_optional_user(authorization: str = Header(default=None), db: Session = Depends(get_db)) -> Optional[User]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    try:
        user_id = decode_token(authorization.split(" ", 1)[1])
        return db.query(User).get(user_id)
    except HTTPException:
        return None


# ---------- Schemas ----------

class RegisterIn(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ContactIn(BaseModel):
    name: str
    phone: str
    relation: str = ""


class ResponderIn(BaseModel):
    name: str
    phone: str
    responder_type: str = "volunteer"
    lat: float
    lng: float


class IncidentIn(BaseModel):
    lat: float
    lng: float
    requester_name: Optional[str] = None
    requester_phone: Optional[str] = None


class StatusIn(BaseModel):
    status: str


class ChatIn(BaseModel):
    query: str
    incident_category: Optional[str] = None


class UnsafeAreaIn(BaseModel):
    lat: float
    lng: float
    category: str = "poor_lighting"
    severity: int = 2
    notes: str = ""


class SafetyAuditIn(BaseModel):
    lat: float
    lng: float
    lighting: int = 3
    openness: int = 3
    visibility: int = 3
    people_presence: int = 3
    security: int = 3
    walk_path: int = 3
    public_transport: int = 3
    gender_usage: int = 3
    feeling: int = 3
    notes: str = ""


# ---------- Auth ----------

@app.post("/auth/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="An account with this email already exists")
    user = User(
        name=payload.name,
        email=payload.email,
        phone=payload.phone,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_token(user.id)
    return {"token": token, "user": {"id": user.id, "name": user.name, "email": user.email}}


@app.post("/auth/login")
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_token(user.id)
    return {"token": token, "user": {"id": user.id, "name": user.name, "email": user.email}}


@app.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "name": user.name, "email": user.email, "phone": user.phone}


# ---------- Trusted contacts ----------

@app.post("/contacts")
def add_contact(payload: ContactIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    contact = TrustedContact(user_id=user.id, **payload.dict())
    db.add(contact)
    db.commit()
    db.refresh(contact)
    return contact


@app.get("/contacts")
def list_contacts(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(TrustedContact).filter(TrustedContact.user_id == user.id).all()


@app.delete("/contacts/{contact_id}")
def delete_contact(contact_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    contact = db.query(TrustedContact).filter(TrustedContact.id == contact_id, TrustedContact.user_id == user.id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(contact)
    db.commit()
    return {"ok": True}


# ---------- Responders ----------

@app.post("/responders")
def create_responder(payload: ResponderIn, db: Session = Depends(get_db)):
    r = Responder(**payload.dict(), is_available="true")
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


@app.get("/responders")
def list_responders(db: Session = Depends(get_db)):
    return db.query(Responder).all()


# ---------- Unsafe area reporting ----------

@app.post("/unsafe-areas")
def report_unsafe_area(payload: UnsafeAreaIn, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    area = UnsafeArea(
        reported_by_user_id=user.id if user else None,
        **payload.dict(),
    )
    db.add(area)
    db.commit()
    db.refresh(area)
    return area


@app.get("/unsafe-areas")
def list_unsafe_areas(db: Session = Depends(get_db)):
    areas = db.query(UnsafeArea).order_by(UnsafeArea.created_at.desc()).all()
    return [
        {
            "id": a.id,
            "lat": a.lat,
            "lng": a.lng,
            "category": a.category,
            "severity": a.severity,
            "notes": a.notes,
            "created_at": a.created_at.isoformat(),
        }
        for a in areas
    ]


# ---------- Safety audits (Safetipin-style multi-parameter score) ----------

@app.post("/safety-audits")
def create_safety_audit(payload: SafetyAuditIn, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    audit = SafetyAudit(
        reported_by_user_id=user.id if user else None,
        **payload.dict(),
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)
    return {
        "id": audit.id,
        "lat": audit.lat,
        "lng": audit.lng,
        "safety_score": audit.safety_score,
        "created_at": audit.created_at.isoformat(),
    }


@app.get("/safety-audits")
def list_safety_audits(db: Session = Depends(get_db)):
    audits = db.query(SafetyAudit).order_by(SafetyAudit.created_at.desc()).all()
    return [
        {
            "id": a.id,
            "lat": a.lat,
            "lng": a.lng,
            "safety_score": a.safety_score,
            "lighting": a.lighting,
            "openness": a.openness,
            "visibility": a.visibility,
            "people_presence": a.people_presence,
            "security": a.security,
            "walk_path": a.walk_path,
            "public_transport": a.public_transport,
            "gender_usage": a.gender_usage,
            "feeling": a.feeling,
            "notes": a.notes,
            "created_at": a.created_at.isoformat(),
        }
        for a in audits
    ]


@app.get("/safety-audits/area-score")
def area_safety_score(lat: float, lng: float, radius_km: float = 0.5, db: Session = Depends(get_db)):
    audits = db.query(SafetyAudit).all()
    nearby = [a for a in audits if haversine_km(lat, lng, a.lat, a.lng) <= radius_km]
    if not nearby:
        return {"score": None, "sample_size": 0, "message": "No safety audits reported near this location yet"}
    avg_score = round(sum(a.safety_score for a in nearby) / len(nearby), 2)
    return {"score": avg_score, "sample_size": len(nearby), "radius_km": radius_km}


# ---------- Incidents / matching ----------

@app.post("/incidents")
def trigger_sos(payload: IncidentIn, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    if user:
        requester_name = user.name
        requester_phone = user.phone
    else:
        if not payload.requester_name or not payload.requester_phone:
            raise HTTPException(status_code=400, detail="requester_name and requester_phone are required when not logged in")
        requester_name = payload.requester_name
        requester_phone = payload.requester_phone

    available = db.query(Responder).filter(Responder.is_available == "true").all()
    if not available:
        raise HTTPException(status_code=503, detail="No responders available right now")

    nearest = min(available, key=lambda r: haversine_km(payload.lat, payload.lng, r.lat, r.lng))
    distance = haversine_km(payload.lat, payload.lng, nearest.lat, nearest.lng)

    incident = Incident(
        user_id=user.id if user else None,
        requester_name=requester_name,
        requester_phone=requester_phone,
        lat=payload.lat,
        lng=payload.lng,
        status="matched",
        responder_id=nearest.id,
    )
    nearest.is_available = "false"
    db.add(incident)
    db.commit()
    db.refresh(incident)

    notified_contacts = []
    if user:
        contacts = db.query(TrustedContact).filter(TrustedContact.user_id == user.id).all()
        notified_contacts = [{"name": c.name, "phone": c.phone} for c in contacts]

    return {
        "incident_id": incident.id,
        "status": incident.status,
        "responder": {
            "id": nearest.id,
            "name": nearest.name,
            "phone": nearest.phone,
            "lat": nearest.lat,
            "lng": nearest.lng,
        },
        "distance_km": round(distance, 2),
        "eta_minutes": round(distance / 0.5),
        "notified_contacts": notified_contacts,
    }


@app.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()
    return [
        {
            "id": i.id,
            "requester_name": i.requester_name,
            "status": i.status,
            "lat": i.lat,
            "lng": i.lng,
            "responder_id": i.responder_id,
            "responder_name": i.responder.name if i.responder else None,
            "created_at": i.created_at.isoformat(),
            "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
        }
        for i in incidents
    ]


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.patch("/incidents/{incident_id}/status")
def update_status(incident_id: int, payload: StatusIn, db: Session = Depends(get_db)):
    incident = db.query(Incident).get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = payload.status
    if payload.status in ("resolved", "false_alarm"):
        incident.resolved_at = datetime.utcnow()
        if incident.responder:
            incident.responder.is_available = "true"
    db.commit()
    return {"ok": True, "status": incident.status}


@app.get("/incidents/{incident_id}/report", response_class=PlainTextResponse)
def generate_report(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    report = f"""INCIDENT REPORT — StreeSafe
Generated: {datetime.utcnow().isoformat()} UTC

Incident ID: {incident.id}
Status: {incident.status}
Reported by: {incident.requester_name} ({incident.requester_phone})
Location (lat, lng): {incident.lat}, {incident.lng}
Time reported: {incident.created_at.isoformat()} UTC
Time resolved: {incident.resolved_at.isoformat() + ' UTC' if incident.resolved_at else 'Not yet resolved'}
Responder assigned: {incident.responder.name if incident.responder else 'None'}
Notes: {incident.notes or 'None provided'}

This report was generated by the StreeSafe app for the user's own records
and to make filing a First Information Report (FIR) at the nearest police
station easier. It is not itself a police filing.
"""
    return report


# ---------- Admin stats ----------

@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()
    total = len(incidents)
    resolved = len([i for i in incidents if i.status == "resolved"])
    active = len([i for i in incidents if i.status in ("matched", "en_route")])
    resolved_times = [
        (i.resolved_at - i.created_at).total_seconds() / 60
        for i in incidents
        if i.resolved_at
    ]
    avg_resolution_min = round(sum(resolved_times) / len(resolved_times), 1) if resolved_times else None
    return {
        "total_incidents": total,
        "active_incidents": active,
        "resolved_incidents": resolved,
        "avg_resolution_minutes": avg_resolution_min,
        "responders_online": db.query(Responder).filter(Responder.is_available == "true").count(),
        "unsafe_areas_reported": db.query(UnsafeArea).count(),
    }


# ---------- RAG safety assistant ----------

@app.post("/chat")
def chat(payload: ChatIn):
    return safety_rag.answer(payload.query, payload.incident_category)


# ---------- WebSocket live tracking ----------

class ConnectionManager:
    def __init__(self):
        self.rooms: Dict[int, List[WebSocket]] = {}

    async def connect(self, incident_id: int, ws: WebSocket):
        await ws.accept()
        self.rooms.setdefault(incident_id, []).append(ws)

    def disconnect(self, incident_id: int, ws: WebSocket):
        if incident_id in self.rooms and ws in self.rooms[incident_id]:
            self.rooms[incident_id].remove(ws)

    async def broadcast(self, incident_id: int, message: dict):
        for connection in self.rooms.get(incident_id, []):
            await connection.send_json(message)


manager = ConnectionManager()


@app.websocket("/ws/track/{incident_id}")
async def track(websocket: WebSocket, incident_id: int):
    await manager.connect(incident_id, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            await manager.broadcast(incident_id, {**data, "incident_id": incident_id})
    except WebSocketDisconnect:
        manager.disconnect(incident_id, websocket)
