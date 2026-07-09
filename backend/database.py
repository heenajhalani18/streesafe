from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = "sqlite:///./streesafe.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    phone = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    trusted_contacts = relationship("TrustedContact", back_populates="user")
    incidents = relationship("Incident", back_populates="user")
    unsafe_areas = relationship("UnsafeArea", back_populates="reported_by")


class TrustedContact(Base):
    __tablename__ = "trusted_contacts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    phone = Column(String, nullable=False)
    relation = Column(String, default="")

    user = relationship("User", back_populates="trusted_contacts")


class Responder(Base):
    __tablename__ = "responders"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    phone = Column(String, nullable=False)
    responder_type = Column(String, default="volunteer")  # volunteer | trusted_contact
    lat = Column(Float, default=0.0)
    lng = Column(Float, default=0.0)
    is_available = Column(String, default="true")

    incidents = relationship("Incident", back_populates="responder")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    requester_name = Column(String, nullable=False)
    requester_phone = Column(String, nullable=False)
    lat = Column(Float, nullable=False)
    lng = Column(Float, nullable=False)
    status = Column(String, default="requested")
    # requested -> matched -> en_route -> resolved -> false_alarm
    responder_id = Column(Integer, ForeignKey("responders.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    notes = Column(String, default="")

    responder = relationship("Responder", back_populates="incidents")
    user = relationship("User", back_populates="incidents")


class UnsafeArea(Base):
    __tablename__ = "unsafe_areas"

    id = Column(Integer, primary_key=True, index=True)
    reported_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    lat = Column(Float, nullable=False)
    lng = Column(Float, nullable=False)
    category = Column(String, default="poor_lighting")
    # poor_lighting | harassment_reported | isolated | unsafe_at_night | other
    severity = Column(Integer, default=2)  # 1 (low) - 3 (high)
    notes = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    reported_by = relationship("User", back_populates="unsafe_areas")


class SafetyAudit(Base):
    __tablename__ = "safety_audits"

    id = Column(Integer, primary_key=True, index=True)
    reported_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    lat = Column(Float, nullable=False)
    lng = Column(Float, nullable=False)
    lighting = Column(Integer, default=3)        # 1-5
    openness = Column(Integer, default=3)
    visibility = Column(Integer, default=3)
    people_presence = Column(Integer, default=3)
    security = Column(Integer, default=3)
    walk_path = Column(Integer, default=3)
    public_transport = Column(Integer, default=3)
    gender_usage = Column(Integer, default=3)
    feeling = Column(Integer, default=3)
    notes = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    @property
    def safety_score(self):
        vals = [
            self.lighting, self.openness, self.visibility, self.people_presence,
            self.security, self.walk_path, self.public_transport, self.gender_usage,
            self.feeling,
        ]
        return round(sum(vals) / len(vals), 2)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
