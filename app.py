# ============================================================
# MIS v2 — Case-Centric Intelligence Platform
# Timeline Entry → Intelligence / Media / Entities / Sources
# Analyst View · Relationships · Real Media Encryption
# ============================================================

import os
import io
import hashlib
import secrets
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, send_file, abort, jsonify
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import (
    StringField, PasswordField, TextAreaField, SelectField,
    BooleanField, SubmitField, IntegerField, DateTimeField
)
from wtforms.validators import DataRequired, Length, EqualTo, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy import or_, and_

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib import colors

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ============================================================
# CONFIG
# ============================================================
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))

    _db = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'mis.db')}"
    )
    if _db.startswith("postgres://"):
        _db = _db.replace("postgres://", "postgresql://", 1)

    SQLALCHEMY_DATABASE_URI = _db
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 300}

    WTF_CSRF_TIME_LIMIT = None
    MAX_CONTENT_LENGTH = 60 * 1024 * 1024

    INITIAL_USERNAME = os.getenv("INITIAL_USERNAME", "Mpc")
    INITIAL_PASSWORD = os.getenv("INITIAL_PASSWORD", "08800Mpc!")


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in."


# ============================================================
# CONSTANTS
# ============================================================
CLEARANCE_LEVELS = [
    ("CONFIDENTIAL", "CONFIDENTIAL"),
    ("SECRET", "SECRET"),
    ("TOP_SECRET", "TOP SECRET"),
    ("EYES_ONLY", "EYES ONLY"),
]

CLASSIFICATIONS = [
    ("UNCLASSIFIED", "UNCLASSIFIED"),
    ("CONFIDENTIAL", "CONFIDENTIAL"),
    ("SECRET", "SECRET"),
    ("TOP_SECRET", "TOP SECRET"),
]

THREAT_LEVELS = [
    ("LOW", "LOW"),
    ("MEDIUM", "MEDIUM"),
    ("HIGH", "HIGH"),
    ("CRITICAL", "CRITICAL"),
]

# NATO-style source reliability (A = fully reliable, F = cannot be judged)
SOURCE_RELIABILITY = [
    ("A", "A — Completely reliable"),
    ("B", "B — Usually reliable"),
    ("C", "C — Fairly reliable"),
    ("D", "D — Not usually reliable"),
    ("E", "E — Unreliable"),
    ("F", "F — Cannot be judged"),
]

INFO_CONFIDENCE = [
    ("1", "1 — Confirmed by other sources"),
    ("2", "2 — Probably true"),
    ("3", "3 — Possibly true"),
    ("4", "4 — Doubtful"),
    ("5", "5 — Improbable"),
    ("6", "6 — Cannot be judged"),
]

INTEL_STATUS = [
    ("UNVERIFIED", "UNVERIFIED"),
    ("CORROBORATED", "CORROBORATED"),
    ("VERIFIED", "VERIFIED"),
    ("DISPUTED", "DISPUTED"),
    ("FALSE", "FALSE"),
]

INTEL_CATEGORIES = [
    ("OBSERVATION", "OBSERVATION"),
    ("SOURCE_REPORT", "SOURCE REPORT"),
    ("DOCUMENT", "DOCUMENT"),
    ("IMAGE_ANALYSIS", "IMAGE ANALYSIS"),
    ("AUDIO_ANALYSIS", "AUDIO ANALYSIS"),
    ("MEETING", "MEETING"),
    ("MOVEMENT", "MOVEMENT"),
    ("COMMUNICATION", "COMMUNICATION"),
    ("OTHER", "OTHER"),
]

ANALYST_CATEGORIES = [
    ("FACT", "FACT"),
    ("CLAIM", "CLAIM"),
    ("CORROBORATED", "CORROBORATED"),
    ("UNVERIFIED", "UNVERIFIED"),
    ("ASSESSMENT", "ANALYTIC ASSESSMENT"),
    ("QUESTION", "OPEN QUESTION"),
    ("CONTRADICTION", "CONTRADICTION"),
]

RELATION_TYPES = [
    ("associated_with", "associated with"),
    ("family_of", "family of"),
    ("works_for", "works for"),
    ("member_of", "member of"),
    ("owns", "owns"),
    ("located_at", "located at"),
    ("met_with", "met with"),
    ("communicated_with", "communicated with"),
    ("seen_with", "seen with"),
    ("suspects", "suspected of involvement with"),
    ("witness_of", "witness of"),
    ("other", "other"),
]

REGIONS = [
    ("—", 0, 0),
    ("Kampala, UG", 0.3476, 32.5825),
    ("Nairobi, KE", -1.2921, 36.8219),
    ("Dar es Salaam, TZ", -6.7924, 39.2083),
    ("Kigali, RW", -1.9441, 30.0619),
    ("Addis Ababa, ET", 9.0300, 38.7400),
    ("Cairo, EG", 30.0444, 31.2357),
    ("Lagos, NG", 6.5244, 3.3792),
    ("Johannesburg, ZA", -26.2041, 28.0473),
    ("London, UK", 51.5074, -0.1278),
    ("Dubai, AE", 25.2048, 55.2708),
    ("Washington DC, US", 38.9072, -77.0369),
    ("Langley, US (CIA)", 38.9517, -77.1467),
]
REGION_MAP = {name: (lat, lng) for (name, lat, lng) in REGIONS}


# ============================================================
# MODELS
# ============================================================
class User(UserMixin, db.Model):
    __tablename__ = "mis_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    codename = db.Column(db.String(80), default="")
    clearance = db.Column(db.String(40), default="SECRET")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw, method="pbkdf2:sha256", salt_length=16)

    def check_password(self, raw):
        h = (self.password_hash or "").strip()
        if not h or ":" not in h:
            return False
        try:
            return check_password_hash(h, raw)
        except Exception:
            return False


class Case(db.Model):
    __tablename__ = "mis_cases"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    objective = db.Column(db.Text, default="")
    status = db.Column(db.String(40), default="Active")
    classification = db.Column(db.String(40), default="SECRET")
    threat_level = db.Column(db.String(20), default="MEDIUM")
    priority = db.Column(db.Integer, default=3)
    due_date = db.Column(db.DateTime, nullable=True)
    subject = db.Column(db.String(200), default="")   # who/what the case is about
    legal_note = db.Column(db.Text, default="")        # chain of custody / purpose
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    timeline = db.relationship("TimelineEntry", backref="case", lazy=True,
                               cascade="all, delete-orphan", order_by="TimelineEntry.event_at.desc()")
    intel = db.relationship("IntelItem", backref="case", lazy=True,
                            cascade="all, delete-orphan", order_by="IntelItem.created_at.desc()")
    media = db.relationship("MediaItem", backref="case", lazy=True,
                            cascade="all, delete-orphan", order_by="MediaItem.created_at.desc()")
    links = db.relationship("CaseEntity", backref="case", lazy=True,
                            cascade="all, delete-orphan")
    analyst = db.relationship("AnalystNote", backref="case", lazy=True,
                              cascade="all, delete-orphan", order_by="AnalystNote.created_at.desc()")


class Entity(db.Model):
    __tablename__ = "mis_entities"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(60), default="Person")
    notes = db.Column(db.Text, default="")
    verified = db.Column(db.Boolean, default=False)
    threat_level = db.Column(db.String(20), default="LOW")
    region = db.Column(db.String(120), default="")
    latitude = db.Column(db.Float, default=0)
    longitude = db.Column(db.Float, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    outgoing = db.relationship("Relationship", foreign_keys="Relationship.from_id",
                               backref="from_entity", lazy=True, cascade="all, delete-orphan")
    incoming = db.relationship("Relationship", foreign_keys="Relationship.to_id",
                               backref="to_entity", lazy=True, cascade="all, delete-orphan")


class CaseEntity(db.Model):
    """Which entities are attached to which case."""
    __tablename__ = "mis_case_entities"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    entity_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    role = db.Column(db.String(80), default="POI")  # POI, SUSPECT, WITNESS, SOURCE, VICTIM, etc.
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    entity = db.relationship("Entity")


class Relationship(db.Model):
    __tablename__ = "mis_relationships"
    id = db.Column(db.Integer, primary_key=True)
    from_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    to_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    relation = db.Column(db.String(80), default="associated_with")
    description = db.Column(db.Text, default="")
    status = db.Column(db.String(20), default="UNVERIFIED")
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Source(db.Model):
    __tablename__ = "mis_sources"
    id = db.Column(db.Integer, primary_key=True)
    handle = db.Column(db.String(120), nullable=False)      # e.g. "S1", "Source Alpha"
    description = db.Column(db.Text, default="")
    reliability = db.Column(db.String(2), default="F")      # A–F
    contact_notes = db.Column(db.Text, default="")
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TimelineEntry(db.Model):
    """Central object. Everything hangs off this."""
    __tablename__ = "mis_timeline"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")
    event_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    category = db.Column(db.String(40), default="OBSERVATION")
    classification = db.Column(db.String(40), default="SECRET")
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    intel = db.relationship("IntelItem", backref="timeline_entry", lazy=True)
    media = db.relationship("MediaItem", backref="timeline_entry", lazy=True)


class IntelItem(db.Model):
    __tablename__ = "mis_intel"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=True)
    timeline_id = db.Column(db.Integer, db.ForeignKey("mis_timeline.id"), nullable=True)
    source_id = db.Column(db.Integer, db.ForeignKey("mis_sources.id"), nullable=True)

    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, default="")
    category = db.Column(db.String(40), default="OBSERVATION")
    classification = db.Column(db.String(40), default="SECRET")

    # Source reliability A–F
    source_reliability = db.Column(db.String(2), default="F")
    # Info confidence 1–6
    info_confidence = db.Column(db.String(2), default="6")
    # STATUS: UNVERIFIED / CORROBORATED / VERIFIED / DISPUTED / FALSE
    status = db.Column(db.String(20), default="UNVERIFIED")
    # Is this a fact, a claim, an observation, an assessment?
    is_fact = db.Column(db.Boolean, default=False)
    is_claim = db.Column(db.Boolean, default=False)

    analyst_comment = db.Column(db.Text, default="")
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    source = db.relationship("Source")


class MediaItem(db.Model):
    __tablename__ = "mis_media"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=True)
    timeline_id = db.Column(db.Integer, db.ForeignKey("mis_timeline.id"), nullable=True)

    title = db.Column(db.String(200), nullable=False)
    kind = db.Column(db.String(20), default="IMAGE")  # IMAGE / AUDIO / VIDEO / DOCUMENT
    filename = db.Column(db.String(255))
    mimetype = db.Column(db.String(120), default="application/octet-stream")
    description = db.Column(db.Text, default="")
    source_notes = db.Column(db.Text, default="")
    classification = db.Column(db.String(40), default="SECRET")

    # ORIGINAL vs ANALYSIS COPY
    is_original = db.Column(db.Boolean, default=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("mis_media.id"), nullable=True)
    derived_note = db.Column(db.Text, default="")  # e.g. "cropped", "enhanced", "blurred"

    # Encrypted payload (bytes) + metadata
    data = db.Column(db.LargeBinary)
    sha256 = db.Column(db.String(64), index=True)
    encrypted = db.Column(db.Boolean, default=False)

    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    parent = db.relationship("MediaItem", remote_side=[id], backref="derivatives")


class AnalystNote(db.Model):
    __tablename__ = "mis_analyst"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    category = db.Column(db.String(40), default="FACT")
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, default="")
    # Links to intel items this note refers to (comma-separated IDs, kept simple)
    linked_intel_ids = db.Column(db.String(500), default="")
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class DeadDrop(db.Model):
    __tablename__ = "mis_dead_drops"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, default="")
    unlock_at = db.Column(db.DateTime, nullable=False)
    classification = db.Column(db.String(40), default="TOP_SECRET")
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_unlocked(self):
        return datetime.utcnow() >= self.unlock_at

    @property
    def countdown(self):
        if self.is_unlocked:
            return "UNLOCKED"
        d = self.unlock_at - datetime.utcnow()
        return f"{d.days}d {d.seconds//3600:02d}:{(d.seconds%3600)//60:02d}:{d.seconds%60:02d}"


class AuditLog(db.Model):
    __tablename__ = "mis_audit_log"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(80))
    detail = db.Column(db.Text)
    actor = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def audit(action, detail="", actor="system"):
    try:
        db.session.add(AuditLog(action=action, detail=detail, actor=actor))
        db.session.commit()
    except Exception:
        db.session.rollback()


@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


# ============================================================
# FORMS
# ============================================================
class LoginForm(FlaskForm):
    username = StringField("Agent ID", validators=[DataRequired(), Length(1, 80)])
    password = PasswordField("Passphrase", validators=[DataRequired()])
    submit = SubmitField("Access")


class ChangePasswordForm(FlaskForm):
    current = PasswordField("Current Passphrase", validators=[DataRequired()])
    new = PasswordField("New Passphrase", validators=[DataRequired(), Length(min=10)])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("new")])
    submit = SubmitField("Rotate")


class AgentForm(FlaskForm):
    username = StringField("Agent ID", validators=[DataRequired(), Length(3, 80)])
    password = PasswordField("Passphrase", validators=[DataRequired(), Length(min=8)])
    codename = StringField("Codename", validators=[Optional(), Length(0, 80)])
    clearance = SelectField("Clearance", choices=CLEARANCE_LEVELS)
    submit = SubmitField("Register Agent")


class CaseForm(FlaskForm):
    title = StringField("Case Title", validators=[DataRequired(), Length(1, 200)])
    subject = StringField("Subject", validators=[Optional(), Length(0, 200)])
    objective = TextAreaField("Objective")
    legal_note = TextAreaField("Purpose / Authority / Legal Basis")
    status = SelectField("Status", choices=[
        ("Active", "Active"), ("Review", "Review"),
        ("Closed", "Closed"), ("Archived", "Archived")
    ])
    classification = SelectField("Classification", choices=CLASSIFICATIONS)
    threat_level = SelectField("Threat Level", choices=THREAT_LEVELS)
    priority = SelectField("Priority", coerce=int, choices=[
        (1, "1 — CRITICAL"), (2, "2 — HIGH"), (3, "3 — MEDIUM"), (4, "4 — LOW")
    ])
    due_date = DateTimeField("Due (YYYY-MM-DD HH:MM)", format="%Y-%m-%d %H:%M", validators=[Optional()])
    submit = SubmitField("Save")


class TimelineForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    description = TextAreaField("Description")
    event_at = DateTimeField("Event Date/Time (YYYY-MM-DD HH:MM)",
                             format="%Y-%m-%d %H:%M", validators=[DataRequired()])
    category = SelectField("Category", choices=INTEL_CATEGORIES)
    classification = SelectField("Classification", choices=CLASSIFICATIONS)
    submit = SubmitField("Add to Timeline")


class IntelForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    body = TextAreaField("Statement", validators=[DataRequired()])
    category = SelectField("Category", choices=INTEL_CATEGORIES)
    classification = SelectField("Classification", choices=CLASSIFICATIONS)
    source_id = SelectField("Source", coerce=int, validators=[Optional()])
    source_reliability = SelectField("Source Reliability", choices=SOURCE_RELIABILITY)
    info_confidence = SelectField("Information Confidence", choices=INFO_CONFIDENCE)
    status = SelectField("Status", choices=INTEL_STATUS)
    is_fact = BooleanField("Mark as established FACT (only if independently verified)")
    is_claim = BooleanField("Mark as CLAIM (statement made by a source)")
    analyst_comment = TextAreaField("Analyst Comment")
    timeline_id = SelectField("Attach to Timeline Entry", coerce=int, validators=[Optional()])
    submit = SubmitField("File Intel Item")


class EntityForm(FlaskForm):
    name = StringField("Name / Codename", validators=[DataRequired(), Length(1, 200)])
    type = SelectField("Type", choices=[
        ("Person", "Person"), ("Organization", "Organization"), ("Company", "Company"),
        ("Location", "Location"), ("Vehicle", "Vehicle"), ("Event", "Event"),
        ("Project", "Project"), ("Website", "Website")
    ])
    notes = TextAreaField("Notes")
    verified = BooleanField("Verified")
    threat_level = SelectField("Threat Level", choices=THREAT_LEVELS)
    region = SelectField("Region", choices=[(r[0], r[0]) for r in REGIONS])
    submit = SubmitField("Save Entity")


class CaseEntityForm(FlaskForm):
    entity_id = SelectField("Entity", coerce=int, validators=[DataRequired()])
    role = SelectField("Role", choices=[
        ("POI", "POI"), ("SUSPECT", "SUSPECT"), ("WITNESS", "WITNESS"),
        ("SOURCE", "SOURCE"), ("VICTIM", "VICTIM"), ("ASSOCIATE", "ASSOCIATE"),
        ("FAMILY", "FAMILY"), ("OTHER", "OTHER")
    ])
    submit = SubmitField("Attach to Case")


class RelationshipForm(FlaskForm):
    from_id = SelectField("From", coerce=int, validators=[DataRequired()])
    to_id = SelectField("To", coerce=int, validators=[DataRequired()])
    relation = SelectField("Relation", choices=RELATION_TYPES)
    description = TextAreaField("Description")
    status = SelectField("Status", choices=INTEL_STATUS)
    submit = SubmitField("Create Relationship")


class SourceForm(FlaskForm):
    handle = StringField("Source Handle", validators=[DataRequired(), Length(1, 120)])
    description = TextAreaField("Description")
    reliability = SelectField("Reliability", choices=SOURCE_RELIABILITY)
    contact_notes = TextAreaField("Contact Notes (do NOT store PII you are not authorised to keep)")
    submit = SubmitField("Save Source")


class MediaForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    kind = SelectField("Kind", choices=[
        ("IMAGE", "IMAGE"), ("AUDIO", "AUDIO"),
        ("VIDEO", "VIDEO"), ("DOCUMENT", "DOCUMENT")
    ])
    file = FileField("File", validators=[FileRequired()])
    description = TextAreaField("Description of what is observed")
    source_notes = TextAreaField("Source / Provenance")
    classification = SelectField("Classification", choices=CLASSIFICATIONS)
    encrypt = BooleanField("Encrypt at rest (requires passphrase to view)")
    passphrase = PasswordField("Encryption Passphrase (if encrypting)")
    parent_id = SelectField("Derived from (original)", coerce=int, validators=[Optional()])
    derived_note = StringField("Derivation note (e.g. cropped, enhanced, blurred)")
    timeline_id = SelectField("Attach to Timeline Entry", coerce=int, validators=[Optional()])
    submit = SubmitField("Secure Media")


class AnalystForm(FlaskForm):
    category = SelectField("Category", choices=ANALYST_CATEGORIES)
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    body = TextAreaField("Body", validators=[DataRequired()])
    linked_intel_ids = StringField("Linked Intel IDs (comma separated)")
    submit = SubmitField("Save Analyst Note")


class DeadDropForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    body = TextAreaField("Body", validators=[DataRequired()])
    unlock_at = DateTimeField("Unlock At (YYYY-MM-DD HH:MM)",
                              format="%Y-%m-%d %H:%M", validators=[DataRequired()])
    classification = SelectField("Classification", choices=CLASSIFICATIONS)
    submit = SubmitField("Seal Dead Drop")


class ReportForm(FlaskForm):
    password = PasswordField("Encryption Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Download Encrypted PDF")


# ============================================================
# HELPERS
# ============================================================
def case_choices():
    rows = db.session.execute(db.select(Case).order_by(Case.id)).scalars().all()
    return [(0, "— none —")] + [(c.id, f"OP-{c.id:04d} {c.title}") for c in rows]


def timeline_choices(case_id=None):
    q = db.select(TimelineEntry)
    if case_id:
        q = q.where(TimelineEntry.case_id == case_id)
    q = q.order_by(TimelineEntry.event_at.desc())
    rows = db.session.execute(q).scalars().all()
    return [(0, "— none —")] + [(t.id, f"{t.event_at.strftime('%Y-%m-%d %H:%M')} · {t.title}") for t in rows]


def entity_choices():
    rows = db.session.execute(db.select(Entity).order_by(Entity.name)).scalars().all()
    return [(e.id, f"{e.name} ({e.type})") for e in rows]


def source_choices():
    rows = db.session.execute(db.select(Source).order_by(Source.handle)).scalars().all()
    return [(0, "— none —")] + [(s.id, f"{s.handle} [{s.reliability}]") for s in rows]


def media_choices(case_id=None):
    q = db.select(MediaItem)
    if case_id:
        q = q.where(MediaItem.case_id == case_id)
    rows = db.session.execute(q.order_by(MediaItem.id)).scalars().all()
    return [(0, "— none —")] + [(m.id, f"#{m.id} {m.title}") for m in rows]


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def threat_color(level):
    return {
        "LOW": "#3fb950", "MEDIUM": "#ffb000",
        "HIGH": "#ff7b00", "CRITICAL": "#ff3b30",
    }.get((level or "").upper(), "#8a8577")


# ============================================================
# MPC ENCRYPTION
# ============================================================
MPC_MAGIC = b"MIS1"
PBKDF2_ITERATIONS = 200_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def mpc_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, associated_data=MPC_MAGIC)
    return MPC_MAGIC + salt + nonce + ct


def mpc_decrypt(blob: bytes, password: str) -> bytes:
    if blob[:4] != MPC_MAGIC:
        raise ValueError("Not an MIS-encrypted payload")
    salt, nonce, ct = blob[4:20], blob[20:32], blob[32:]
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ct, associated_data=MPC_MAGIC)


# ============================================================
# PDF REPORT — Case File
# ============================================================
def build_case_pdf(case: Case) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=1.8 * cm, rightMargin=1.8 * cm,
                            topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                            title=f"MIS Report — OP-{case.id:04d}")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], textColor=colors.HexColor("#1f3a8a"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#1f3a8a"))
    h3 = ParagraphStyle("h3", parent=styles["Heading3"], textColor=colors.HexColor("#333"))
    body = styles["BodyText"]

    story = []
    story.append(Paragraph("MIS CASE FILE", h1))
    story.append(Paragraph("Mugisha's Intelligence System", styles["Italic"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(f"OP-{case.id:04d} — {case.title}", h2))
    story.append(Paragraph(f"Subject: {case.subject or '—'}", body))
    story.append(Paragraph(f"Status: {case.status} · Classification: {case.classification} · Threat: {case.threat_level} · Priority: {case.priority}", body))
    if case.due_date:
        story.append(Paragraph(f"Due: {case.due_date.isoformat()}", body))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", body))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Purpose / Legal Basis", h2))
    story.append(Paragraph(case.legal_note or "Documentation of observations and information. "
        "This file is intended to be handed to appropriate authorities if required.", body))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Objective", h2))
    story.append(Paragraph(case.objective or "—", body))
    story.append(Spacer(1, 0.3 * cm))

    # TIMELINE
    story.append(Paragraph("Timeline", h2))
    if case.timeline:
        for t in sorted(case.timeline, key=lambda x: x.event_at):
            story.append(Paragraph(
                f"<b>{t.event_at.strftime('%Y-%m-%d %H:%M')}</b> · {t.category} · {t.classification}<br>"
                f"<b>{t.title}</b>", h3
            ))
            if t.description:
                story.append(Paragraph(t.description.replace("\n", "<br/>"), body))
            for i in t.intel:
                story.append(Paragraph(
                    f"  ↳ INTEL: {i.title} · Src reliability {i.source_reliability} · "
                    f"Conf {i.info_confidence} · {i.status}", body))
            for m in t.media:
                story.append(Paragraph(
                    f"  ↳ MEDIA: {m.title} ({m.kind}) sha256 {m.sha256[:16]}… "
                    f"{'(encrypted)' if m.encrypted else ''}", body))
            story.append(Spacer(1, 0.2 * cm))
    else:
        story.append(Paragraph("— none —", body))
    story.append(Spacer(1, 0.3 * cm))

    # ANALYST VIEW
    story.append(PageBreak())
    story.append(Paragraph("Analyst View", h2))
    for cat in ["FACT", "CLAIM", "CORROBORATED", "UNVERIFIED", "ASSESSMENT", "QUESTION", "CONTRADICTION"]:
        items = [a for a in case.analyst if a.category == cat]
        if not items:
            continue
        story.append(Paragraph(cat, h3))
        for a in items:
            story.append(Paragraph(f"<b>{a.title}</b>", body))
            story.append(Paragraph(a.body.replace("\n", "<br/>"), body))
            story.append(Spacer(1, 0.15 * cm))

    story.append(PageBreak())
    story.append(Paragraph("Evidence Register", h2))
    if case.media:
        data = [["ID", "Title", "Kind", "Class", "SHA-256", "Enc"]]
        for m in case.media:
            data.append([str(m.id), m.title[:24], m.kind, m.classification,
                         (m.sha256 or "")[:16] + "…", "Y" if m.encrypted else "N"])
        t = Table(data, colWidths=[1 * cm, 5 * cm, 1.8 * cm, 2 * cm, 4.5 * cm, 1 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a8a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("— none —", body))

    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("Entities", h2))
    for link in case.links:
        e = link.entity
        story.append(Paragraph(
            f"<b>{e.name}</b> ({e.type}) · Role: {link.role} · "
            f"Threat: {e.threat_level} · Region: {e.region or '—'}", body))

    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("Chain of Custody / Handling Note", h2))
    story.append(Paragraph(
        "This report is compiled from information collected by the operator. "
        "Sources, reliability, and confidence are marked per item. "
        "Media are preserved with SHA-256 hashes at intake; derived copies are marked as such. "
        "No confrontation, surveillance, or engagement with subjects is authorised by this document. "
        "If information suggests imminent risk to life, contact police/emergency channels.", body))

    doc.build(story)
    return buf.getvalue()


def build_briefing_pdf(days: int = 1) -> bytes:
    since = datetime.utcnow() - timedelta(days=days)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=1.8 * cm, rightMargin=1.8 * cm,
                            topMargin=1.8 * cm, bottomMargin=1.8 * cm)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], textColor=colors.HexColor("#1f3a8a"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#1f3a8a"))
    body = styles["BodyText"]

    story = []
    story.append(Paragraph("MIS DAILY BRIEFING", h1))
    story.append(Paragraph(f"Window: last {days} day(s) · Generated: {datetime.utcnow().isoformat()}Z", body))
    story.append(Spacer(1, 0.4 * cm))

    cases = db.session.execute(db.select(Case).where(Case.created_at >= since)).scalars().all()
    story.append(Paragraph(f"Operations Opened ({len(cases)})", h2))
    for c in cases:
        story.append(Paragraph(
            f"OP-{c.id:04d} — {c.title} · Threat {c.threat_level}", body))

    intel = db.session.execute(db.select(IntelItem).where(IntelItem.created_at >= since)).scalars().all()
    story.append(Paragraph(f"Intel Items ({len(intel)})", h2))
    for i in intel:
        story.append(Paragraph(
            f"• {i.title} · {i.status} · src {i.source_reliability}{i.info_confidence}", body))

    media = db.session.execute(db.select(MediaItem).where(MediaItem.created_at >= since)).scalars().all()
    story.append(Paragraph(f"Media Secured ({len(media)})", h2))
    for m in media:
        story.append(Paragraph(f"• {m.title} ({m.kind}) {(m.sha256 or '')[:16]}…", body))

    doc.build(story)
    return buf.getvalue()


# ============================================================
# ROUTES — AUTH
# ============================================================
@app.route("/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        uname = (form.username.data or "").strip()
        user = db.session.execute(db.select(User).filter_by(username=uname)).scalar()
        if user and user.check_password(form.password.data):
            login_user(user)
            audit("login_success", f"{user.username} logged in", actor=user.username)
            return redirect(url_for("dashboard"))
        audit("login_fail", f"Attempt for {uname}")
        flash("Invalid credentials.", "error")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    audit("logout", current_user.username, actor=current_user.username)
    logout_user()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current.data):
            flash("Current passphrase incorrect.", "error")
        else:
            current_user.set_password(form.new.data)
            db.session.commit()
            audit("password_change", current_user.username, actor=current_user.username)
            flash("Passphrase rotated.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html", form=form)


# ============================================================
# ROUTES — DASHBOARD
# ============================================================
@app.route("/dashboard")
@login_required
def dashboard():
    now = datetime.utcnow()
    stats = {
        "cases": db.session.scalar(db.select(db.func.count(Case.id))) or 0,
        "entities": db.session.scalar(db.select(db.func.count(Entity.id))) or 0,
        "intel": db.session.scalar(db.select(db.func.count(IntelItem.id))) or 0,
        "media": db.session.scalar(db.select(db.func.count(MediaItem.id))) or 0,
        "agents": db.session.scalar(db.select(db.func.count(User.id))) or 0,
        "drops": db.session.scalar(db.select(db.func.count(DeadDrop.id))) or 0,
        "timeline": db.session.scalar(db.select(db.func.count(TimelineEntry.id))) or 0,
        "analyst": db.session.scalar(db.select(db.func.count(AnalystNote.id))) or 0,
    }
    threat_ops = db.session.execute(
        db.select(Case).where(Case.status.in_(["Active", "Review"]))
        .order_by(Case.priority, Case.due_date.asc().nullslast()).limit(5)
    ).scalars().all()

    recent = db.session.execute(
        db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(10)
    ).scalars().all()

    drops = db.session.execute(
        db.select(DeadDrop).where(DeadDrop.unlock_at > now)
        .order_by(DeadDrop.unlock_at).limit(5)
    ).scalars().all()

    return render_template("dashboard.html", stats=stats, recent=recent,
                           threat_ops=threat_ops, drops=drops)


# ============================================================
# ROUTES — CASES
# ============================================================
@app.route("/cases", methods=["GET", "POST"])
@login_required
def cases():
    form = CaseForm()
    if form.validate_on_submit():
        c = Case(
            title=form.title.data,
            subject=form.subject.data or "",
            objective=form.objective.data or "",
            legal_note=form.legal_note.data or "",
            status=form.status.data,
            classification=form.classification.data,
            threat_level=form.threat_level.data,
            priority=form.priority.data or 3,
            due_date=form.due_date.data,
        )
        db.session.add(c)
        db.session.commit()
        audit("case_create", f"OP-{c.id:04d} {c.title}", actor=current_user.username)
        flash("Case file opened.", "success")
        return redirect(url_for("case_detail", cid=c.id))
    rows = db.session.execute(
        db.select(Case).order_by(Case.priority, Case.created_at.desc())
    ).scalars().all()
    return render_template("cases.html", form=form, cases=rows)


@app.route("/cases/<int:cid>", methods=["GET", "POST"])
@login_required
def case_detail(cid):
    c = db.session.get(Case, cid) or abort(404)
    form = CaseForm(obj=c)
    if form.validate_on_submit():
        c.title = form.title.data
        c.subject = form.subject.data or ""
        c.objective = form.objective.data or ""
        c.legal_note = form.legal_note.data or ""
        c.status = form.status.data
        c.classification = form.classification.data
        c.threat_level = form.threat_level.data
        c.priority = form.priority.data or c.priority
        c.due_date = form.due_date.data
        db.session.commit()
        audit("case_update", f"OP-{c.id:04d}", actor=current_user.username)
        flash("Case updated.", "success")
        return redirect(url_for("case_detail", cid=c.id))

    report_form = ReportForm()
    timeline_form = TimelineForm()
    intel_form = IntelForm()
    media_form = MediaForm()
    analyst_form = AnalystForm()
    rel_form = RelationshipForm()
    case_entity_form = CaseEntityForm()
    source_form = SourceForm()

    intel_form.source_id.choices = source_choices()
    intel_form.timeline_id.choices = timeline_choices(c.id)
    media_form.timeline_id.choices = timeline_choices(c.id)
    media_form.parent_id.choices = media_choices(c.id)
    case_entity_form.entity_id.choices = entity_choices()
    rel_form.from_id.choices = entity_choices()
    rel_form.to_id.choices = entity_choices()

    # Analyst view buckets
    analyst_buckets = {}
    for cat, _label in ANALYST_CATEGORIES:
        analyst_buckets[cat] = [a for a in c.analyst if a.category == cat]

    return render_template(
        "case_detail.html",
        case=c,
        form=form,
        report_form=report_form,
        timeline_form=timeline_form,
        intel_form=intel_form,
        media_form=media_form,
        analyst_form=analyst_form,
        rel_form=rel_form,
        case_entity_form=case_entity_form,
        source_form=source_form,
        analyst_buckets=analyst_buckets,
    )


@app.route("/cases/<int:cid>/delete", methods=["POST"])
@login_required
def case_delete(cid):
    c = db.session.get(Case, cid) or abort(404)
    db.session.delete(c)
    db.session.commit()
    audit("case_delete", f"OP-{cid:04d}", actor=current_user.username)
    flash("Case purged.", "success")
    return redirect(url_for("cases"))


@app.route("/cases/<int:cid>/report", methods=["POST"])
@login_required
def case_report(cid):
    c = db.session.get(Case, cid) or abort(404)
    form = ReportForm()
    if not form.validate_on_submit():
        flash("Password required (min 6 chars).", "error")
        return redirect(url_for("case_detail", cid=cid))
    pdf_bytes = build_case_pdf(c)
    encrypted = mpc_encrypt(pdf_bytes, form.password.data)
    audit("report_download", f"OP-{cid:04d}", actor=current_user.username)
    fname = f"MIS_OP{cid:04d}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.mpcenc"
    return send_file(io.BytesIO(encrypted), mimetype="application/octet-stream",
                     as_attachment=True, download_name=fname)


# ============================================================
# ROUTES — TIMELINE
# ============================================================
@app.route("/cases/<int:cid>/timeline", methods=["POST"])
@login_required
def timeline_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    form = TimelineForm()
    if form.validate_on_submit():
        t = TimelineEntry(
            case_id=c.id,
            title=form.title.data,
            description=form.description.data or "",
            event_at=form.event_at.data,
            category=form.category.data,
            classification=form.classification.data,
            created_by=current_user.username,
        )
        db.session.add(t)
        db.session.commit()
        audit("timeline_add", f"OP-{cid:04d} {t.title}", actor=current_user.username)
        flash("Timeline entry added.", "success")
    else:
        flash("Invalid timeline entry.", "error")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/timeline/<int:tid>/delete", methods=["POST"])
@login_required
def timeline_delete(tid):
    t = db.session.get(TimelineEntry, tid) or abort(404)
    cid = t.case_id
    db.session.delete(t)
    db.session.commit()
    audit("timeline_delete", f"#{tid}", actor=current_user.username)
    return redirect(url_for("case_detail", cid=cid))


# ============================================================
# ROUTES — INTEL
# ============================================================
@app.route("/cases/<int:cid>/intel", methods=["POST"])
@login_required
def intel_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    form = IntelForm()
    form.source_id.choices = source_choices()
    form.timeline_id.choices = timeline_choices(c.id)
    if form.validate_on_submit():
        i = IntelItem(
            case_id=c.id,
            timeline_id=form.timeline_id.data or None,
            source_id=form.source_id.data or None,
            title=form.title.data,
            body=form.body.data,
            category=form.category.data,
            classification=form.classification.data,
            source_reliability=form.source_reliability.data,
            info_confidence=form.info_confidence.data,
            status=form.status.data,
            is_fact=form.is_fact.data,
            is_claim=form.is_claim.data,
            analyst_comment=form.analyst_comment.data or "",
            created_by=current_user.username,
        )
        db.session.add(i)
        db.session.commit()
        audit("intel_add", f"{i.title} [{i.status}]", actor=current_user.username)
        flash("Intel item filed.", "success")
    else:
        flash("Invalid intel form.", "error")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/intel/<int:iid>/delete", methods=["POST"])
@login_required
def intel_delete(iid):
    i = db.session.get(IntelItem, iid) or abort(404)
    cid = i.case_id
    db.session.delete(i)
    db.session.commit()
    audit("intel_delete", f"#{iid}", actor=current_user.username)
    return redirect(url_for("case_detail", cid=cid))


@app.route("/intel/<int:iid>/status/<string:new_status>", methods=["POST"])
@login_required
def intel_status(iid, new_status):
    i = db.session.get(IntelItem, iid) or abort(404)
    allowed = [s[0] for s in INTEL_STATUS]
    if new_status in allowed:
        i.status = new_status
        db.session.commit()
        audit("intel_status", f"#{iid} → {new_status}", actor=current_user.username)
    return redirect(url_for("case_detail", cid=i.case_id))


# ============================================================
# ROUTES — MEDIA
# ============================================================
@app.route("/cases/<int:cid>/media", methods=["POST"])
@login_required
def media_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    form = MediaForm()
    form.timeline_id.choices = timeline_choices(c.id)
    form.parent_id.choices = media_choices(c.id)
    if form.validate_on_submit():
        f = form.file.data
        raw = f.read()
        digest = sha256_bytes(raw)

        encrypted = bool(form.encrypt.data)
        if encrypted:
            if not form.passphrase.data or len(form.passphrase.data) < 6:
                flash("Encryption passphrase must be at least 6 characters.", "error")
                return redirect(url_for("case_detail", cid=cid))
            raw = mpc_encrypt(raw, form.passphrase.data)

        m = MediaItem(
            case_id=c.id,
            timeline_id=form.timeline_id.data or None,
            title=form.title.data,
            kind=form.kind.data,
            filename=secure_filename(f.filename or "media.bin"),
            mimetype=f.mimetype or "application/octet-stream",
            description=form.description.data or "",
            source_notes=form.source_notes.data or "",
            classification=form.classification.data,
            is_original=(form.parent_id.data or 0) == 0,
            parent_id=form.parent_id.data or None,
            derived_note=form.derived_note.data or "",
            data=raw,
            sha256=digest,
            encrypted=encrypted,
            created_by=current_user.username,
        )
        db.session.add(m)
        db.session.commit()
        audit("media_add", f"{m.title} ({m.kind}) sha256={digest[:16]}…", actor=current_user.username)
        flash("Media secured.", "success")
    else:
        flash("Invalid media form.", "error")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/media/<int:mid>/view")
@login_required
def media_view(mid):
    m = db.session.get(MediaItem, mid) or abort(404)
    if not m.encrypted:
        return send_file(io.BytesIO(m.data), mimetype=m.mimetype,
                         as_attachment=False, download_name=m.filename)
    # Encrypted: requires passphrase via query param (GET) — kept simple
    pw = request.args.get("pw", "")
    if not pw:
        return render_template("media_unlock.html", media=m)
    try:
        plain = mpc_decrypt(m.data, pw)
    except Exception:
        flash("Decryption failed — wrong passphrase.", "error")
        return redirect(url_for("media_unlock_retry", mid=mid))
    return send_file(io.BytesIO(plain), mimetype=m.mimetype,
                     as_attachment=False, download_name=m.filename)


@app.route("/media/<int:mid>/unlock", methods=["GET", "POST"])
@login_required
def media_unlock_retry(mid):
    m = db.session.get(MediaItem, mid) or abort(404)
    return render_template("media_unlock.html", media=m, retry=True)


@app.route("/media/<int:mid>/download")
@login_required
def media_download(mid):
    m = db.session.get(MediaItem, mid) or abort(404)
    if m.encrypted:
        flash("Media is encrypted. Unlock it first.", "error")
        return redirect(url_for("case_detail", cid=m.case_id))
    return send_file(io.BytesIO(m.data), mimetype=m.mimetype,
                     as_attachment=True, download_name=m.filename)


@app.route("/media/<int:mid>/delete", methods=["POST"])
@login_required
def media_delete(mid):
    m = db.session.get(MediaItem, mid) or abort(404)
    cid = m.case_id
    db.session.delete(m)
    db.session.commit()
    audit("media_delete", f"#{mid}", actor=current_user.username)
    return redirect(url_for("case_detail", cid=cid))


# ============================================================
# ROUTES — ENTITIES
# ============================================================
@app.route("/entities", methods=["GET", "POST"])
@login_required
def entities():
    form = EntityForm()
    if form.validate_on_submit():
        lat, lng = REGION_MAP.get(form.region.data, (0, 0))
        e = Entity(
            name=form.name.data, type=form.type.data,
            notes=form.notes.data or "", verified=form.verified.data,
            threat_level=form.threat_level.data,
            region=form.region.data or "",
            latitude=lat, longitude=lng,
        )
        db.session.add(e)
        db.session.commit()
        audit("entity_create", e.name, actor=current_user.username)
        flash("Entity registered.", "success")
        return redirect(url_for("entities"))
    rows = db.session.execute(db.select(Entity).order_by(Entity.name)).scalars().all()
    return render_template("people.html", form=form, people=rows)


@app.route("/entities/<int:eid>")
@login_required
def entity_detail(eid):
    e = db.session.get(Entity, eid) or abort(404)
    rels_out = e.outgoing
    rels_in = e.incoming
    cases = db.session.execute(
        db.select(CaseEntity).where(CaseEntity.entity_id == eid)
    ).scalars().all()
    return render_template("person_detail.html", entity=e, rels_out=rels_out, rels_in=rels_in, cases=cases)


@app.route("/entities/<int:eid>/delete", methods=["POST"])
@login_required
def entity_delete(eid):
    e = db.session.get(Entity, eid) or abort(404)
    db.session.delete(e)
    db.session.commit()
    audit("entity_delete", e.name, actor=current_user.username)
    return redirect(url_for("entities"))


@app.route("/cases/<int:cid>/entities", methods=["POST"])
@login_required
def case_entity_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    form = CaseEntityForm()
    form.entity_id.choices = entity_choices()
    if form.validate_on_submit():
        link = CaseEntity(case_id=c.id, entity_id=form.entity_id.data, role=form.role.data)
        db.session.add(link)
        db.session.commit()
        audit("case_entity_add", f"OP-{cid:04d} entity#{form.entity_id.data} as {form.role.data}",
              actor=current_user.username)
        flash("Entity attached to case.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/case-entities/<int:link_id>/delete", methods=["POST"])
@login_required
def case_entity_delete(link_id):
    link = db.session.get(CaseEntity, link_id) or abort(404)
    cid = link.case_id
    db.session.delete(link)
    db.session.commit()
    return redirect(url_for("case_detail", cid=cid))


# ============================================================
# ROUTES — RELATIONSHIPS
# ============================================================
@app.route("/relationships", methods=["GET", "POST"])
@login_required
def relationships():
    form = RelationshipForm()
    form.from_id.choices = entity_choices()
    form.to_id.choices = entity_choices()
    if form.validate_on_submit():
        if form.from_id.data == form.to_id.data:
            flash("Cannot relate an entity to itself.", "error")
        else:
            r = Relationship(
                from_id=form.from_id.data, to_id=form.to_id.data,
                relation=form.relation.data,
                description=form.description.data or "",
                status=form.status.data,
                case_id=request.args.get("case_id", type=int),
            )
            db.session.add(r)
            db.session.commit()
            audit("relationship_add", f"{r.from_id}→{r.to_id}", actor=current_user.username)
            flash("Relationship recorded.", "success")
            return redirect(url_for("relationships"))
    rows = db.session.execute(db.select(Relationship).order_by(Relationship.created_at.desc())).scalars().all()
    return render_template("relationships.html", form=form, relationships=rows)


@app.route("/relationships/<int:rid>/delete", methods=["POST"])
@login_required
def relationship_delete(rid):
    r = db.session.get(Relationship, rid) or abort(404)
    db.session.delete(r)
    db.session.commit()
    audit("relationship_delete", f"#{rid}", actor=current_user.username)
    return redirect(url_for("relationships"))


# ============================================================
# ROUTES — SOURCES
# ============================================================
@app.route("/sources", methods=["GET", "POST"])
@login_required
def sources():
    form = SourceForm()
    if form.validate_on_submit():
        s = Source(
            handle=form.handle.data,
            description=form.description.data or "",
            reliability=form.reliability.data,
            contact_notes=form.contact_notes.data or "",
        )
        db.session.add(s)
        db.session.commit()
        audit("source_add", s.handle, actor=current_user.username)
        flash("Source recorded.", "success")
        return redirect(url_for("sources"))
    rows = db.session.execute(db.select(Source).order_by(Source.handle)).scalars().all()
    return render_template("sources.html", form=form, sources=rows)


@app.route("/sources/<int:sid>/delete", methods=["POST"])
@login_required
def source_delete(sid):
    s = db.session.get(Source, sid) or abort(404)
    db.session.delete(s)
    db.session.commit()
    audit("source_delete", s.handle, actor=current_user.username)
    return redirect(url_for("sources"))


# ============================================================
# ROUTES — ANALYST VIEW
# ============================================================
@app.route("/cases/<int:cid>/analyst", methods=["POST"])
@login_required
def analyst_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    form = AnalystForm()
    if form.validate_on_submit():
        a = AnalystNote(
            case_id=c.id,
            category=form.category.data,
            title=form.title.data,
            body=form.body.data,
            linked_intel_ids=form.linked_intel_ids.data or "",
            created_by=current_user.username,
        )
        db.session.add(a)
        db.session.commit()
        audit("analyst_add", f"{a.category}: {a.title}", actor=current_user.username)
        flash("Analyst note saved.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/analyst/<int:aid>/delete", methods=["POST"])
@login_required
def analyst_delete(aid):
    a = db.session.get(AnalystNote, aid) or abort(404)
    cid = a.case_id
    db.session.delete(a)
    db.session.commit()
    return redirect(url_for("case_detail", cid=cid))


# ============================================================
# ROUTES — DEAD DROPS
# ============================================================
@app.route("/drops", methods=["GET", "POST"])
@login_required
def drops():
    form = DeadDropForm()
    if form.validate_on_submit():
        d = DeadDrop(
            title=form.title.data, body=form.body.data,
            unlock_at=form.unlock_at.data,
            classification=form.classification.data,
            created_by=current_user.username,
        )
        db.session.add(d)
        db.session.commit()
        audit("dead_drop_create", d.title, actor=current_user.username)
        flash("Dead drop sealed.", "success")
        return redirect(url_for("drops"))
    rows = db.session.execute(db.select(DeadDrop).order_by(DeadDrop.unlock_at)).scalars().all()
    return render_template("drops.html", form=form, drops=rows)


@app.route("/drops/<int:did>/delete", methods=["POST"])
@login_required
def drop_delete(did):
    d = db.session.get(DeadDrop, did) or abort(404)
    db.session.delete(d)
    db.session.commit()
    return redirect(url_for("drops"))


# ============================================================
# ROUTES — THREAT BOARD + MAP
# ============================================================
@app.route("/threat-board")
@login_required
def threat_board():
    ops = db.session.execute(
        db.select(Case).where(Case.status.in_(["Active", "Review"]))
        .order_by(Case.priority, Case.due_date.asc().nullslast())
    ).scalars().all()
    groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for op in ops:
        groups.setdefault(op.threat_level, []).append(op)
    return render_template("threat_board.html", groups=groups)


@app.route("/map")
@login_required
def map_view():
    people = db.session.execute(
        db.select(Entity).where(or_(Entity.latitude != 0, Entity.longitude != 0))
    ).scalars().all()
    markers = [{
        "id": p.id, "name": p.name, "type": p.type,
        "threat": p.threat_level, "region": p.region,
        "lat": p.latitude, "lng": p.longitude,
        "verified": p.verified, "color": threat_color(p.threat_level),
    } for p in people]
    return render_template("map.html", markers=markers)


# ============================================================
# ROUTES — BRIEFING
# ============================================================
@app.route("/briefing")
@login_required
def briefing():
    days = int(request.args.get("days", 1))
    since = datetime.utcnow() - timedelta(days=days)
    cases = db.session.execute(db.select(Case).where(Case.created_at >= since).order_by(Case.priority)).scalars().all()
    intel = db.session.execute(db.select(IntelItem).where(IntelItem.created_at >= since).order_by(IntelItem.created_at.desc())).scalars().all()
    media = db.session.execute(db.select(MediaItem).where(MediaItem.created_at >= since).order_by(MediaItem.created_at.desc())).scalars().all()
    entities = db.session.execute(db.select(Entity).where(Entity.created_at >= since).order_by(Entity.name)).scalars().all()
    return render_template("briefing.html", days=days, since=since,
                           cases=cases, intel=intel, media=media, entities=entities)


@app.route("/briefing.pdf", methods=["POST"])
@login_required
def briefing_pdf():
    form = ReportForm()
    if not form.validate_on_submit():
        flash("Password required.", "error")
        return redirect(url_for("briefing"))
    days = int(request.form.get("days", 1))
    pdf_bytes = build_briefing_pdf(days)
    encrypted = mpc_encrypt(pdf_bytes, form.password.data)
    audit("briefing_download", f"{days}d briefing", actor=current_user.username)
    fname = f"MIS_Briefing_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.mpcenc"
    return send_file(io.BytesIO(encrypted), mimetype="application/octet-stream",
                     as_attachment=True, download_name=fname)


# ============================================================
# ROUTES — SEARCH + AUDIT
# ============================================================
@app.route("/search")
@login_required
def search():
    q = (request.args.get("q") or "").strip()
    results = {"intel": [], "entities": [], "cases": [], "media": [], "timeline": []}
    if q:
        like = f"%{q}%"
        results["intel"] = db.session.execute(
            db.select(IntelItem).where(or_(IntelItem.title.ilike(like), IntelItem.body.ilike(like)))
        ).scalars().all()
        results["entities"] = db.session.execute(
            db.select(Entity).where(or_(Entity.name.ilike(like), Entity.notes.ilike(like)))
        ).scalars().all()
        results["cases"] = db.session.execute(
            db.select(Case).where(or_(Case.title.ilike(like), Case.objective.ilike(like), Case.subject.ilike(like)))
        ).scalars().all()
        results["media"] = db.session.execute(
            db.select(MediaItem).where(or_(MediaItem.title.ilike(like), MediaItem.description.ilike(like)))
        ).scalars().all()
        results["timeline"] = db.session.execute(
            db.select(TimelineEntry).where(or_(TimelineEntry.title.ilike(like), TimelineEntry.description.ilike(like)))
        ).scalars().all()
    return render_template("search.html", q=q, results=results)


@app.route("/audit")
@login_required
def audit_log():
    rows = db.session.execute(
        db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(300)
    ).scalars().all()
    return render_template("audit.html", entries=rows)


# ============================================================
# ROUTES — AGENTS
# ============================================================
@app.route("/agents", methods=["GET", "POST"])
@login_required
def agents():
    form = AgentForm()
    if form.validate_on_submit():
        uname = form.username.data.strip()
        existing = db.session.execute(db.select(User).filter_by(username=uname)).scalar()
        if existing:
            flash("Agent ID already in use.", "error")
        else:
            u = User(username=uname, codename=form.codename.data or "",
                     clearance=form.clearance.data)
            u.set_password(form.password.data)
            db.session.add(u)
            db.session.commit()
            audit("agent_register", uname, actor=current_user.username)
            flash("Agent registered.", "success")
            return redirect(url_for("agents"))
    rows = db.session.execute(db.select(User).order_by(User.created_at)).scalars().all()
    return render_template("agents.html", form=form, agents=rows)


@app.route("/agents/<int:uid>/delete", methods=["POST"])
@login_required
def agent_delete(uid):
    if uid == current_user.id:
        flash("Cannot delete your own account.", "error")
        return redirect(url_for("agents"))
    u = db.session.get(User, uid) or abort(404)
    db.session.delete(u)
    db.session.commit()
    return redirect(url_for("agents"))


# ============================================================
# BOOTSTRAP
# ============================================================
def bootstrap():
    with app.app_context():
        db.create_all()

        u = app.config["INITIAL_USERNAME"]
        p = app.config["INITIAL_PASSWORD"]
        force = os.getenv("FORCE_SEED", "0") == "1"

        existing = db.session.execute(db.select(User).filter_by(username=u)).scalar()

        if force:
            User.query.delete()
            db.session.commit()
            user = User(username=u, codename="ALPHA", clearance="EYES_ONLY")
            user.set_password(p)
            db.session.add(user)
            db.session.commit()
            print(f"🔥 Force-reseeded user: {u}")
            return

        if not existing:
            user = User(username=u, codename="ALPHA", clearance="EYES_ONLY")
            user.set_password(p)
            db.session.add(user)
            db.session.commit()
            print(f"✅ Seeded user: {u}")
        else:
            h = (existing.password_hash or "").strip()
            if not h or ":" not in h:
                existing.set_password(p)
                db.session.commit()
                print(f"🩹 Repaired hash for {u}")
            else:
                print(f"✅ User {u} hash OK")


bootstrap()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
