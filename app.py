# ============================================================
# MIS v3 — Plain English Case Tracker
# Quick-Add everywhere · Native phone gallery · Simple labels
# ============================================================

import os
import io
import hashlib
import secrets
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, send_file, abort, jsonify, g
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
    BooleanField, SubmitField, DateTimeField
)
from wtforms.validators import DataRequired, Length, EqualTo, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy import or_, text, inspect

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

    _db = os.getenv("DATABASE_URL",
                    f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'mis.db')}")
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
    subject = db.Column(db.String(200), default="")
    notes = db.Column(db.Text, default="")
    objective = db.Column(db.Text, default="")
    legal_note = db.Column(db.Text, default="")
    status = db.Column(db.String(40), default="Active")
    classification = db.Column(db.String(40), default="SECRET")
    threat_level = db.Column(db.String(20), default="MEDIUM")
    priority = db.Column(db.Integer, default=3)
    due_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    updates = db.relationship(
        "Update", backref="case", lazy=True,
        cascade="all, delete-orphan",
        order_by="Update.happened_at.desc()"
    )
    timeline = db.relationship("TimelineEntry", backref="case", lazy=True,
                               cascade="all, delete-orphan")
    intel = db.relationship("IntelItem", backref="case", lazy=True,
                            cascade="all, delete-orphan")
    media = db.relationship("MediaItem", backref="case", lazy=True,
                            cascade="all, delete-orphan")
    links = db.relationship("CaseEntity", backref="case", lazy=True,
                            cascade="all, delete-orphan")
    analyst = db.relationship("AnalystNote", backref="case", lazy=True,
                              cascade="all, delete-orphan")


class Update(db.Model):
    """A single piece of news you learned about a case."""
    __tablename__ = "mis_updates"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    body = db.Column(db.Text, default="")
    happened_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    photos = db.relationship("UpdateMedia", backref="update", lazy=True,
                             cascade="all, delete-orphan",
                             order_by="UpdateMedia.id")


class UpdateMedia(db.Model):
    """Photo/voice attached to a news update."""
    __tablename__ = "mis_update_media"
    id = db.Column(db.Integer, primary_key=True)
    update_id = db.Column(db.Integer, db.ForeignKey("mis_updates.id"), nullable=False)
    kind = db.Column(db.String(20), default="photo")  # photo | voice | file
    filename = db.Column(db.String(255))
    mimetype = db.Column(db.String(120), default="application/octet-stream")
    data = db.Column(db.LargeBinary)
    sha256 = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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


class CaseEntity(db.Model):
    __tablename__ = "mis_case_entities"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    entity_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    role = db.Column(db.String(80), default="Person")
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    entity = db.relationship("Entity")


class Relationship(db.Model):
    __tablename__ = "mis_relationships"
    id = db.Column(db.Integer, primary_key=True)
    from_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    to_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    relation = db.Column(db.String(80), default="knows")
    description = db.Column(db.Text, default="")
    status = db.Column(db.String(20), default="UNVERIFIED")
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    from_entity = db.relationship("Entity", foreign_keys=[from_id], backref="outgoing")
    to_entity = db.relationship("Entity", foreign_keys=[to_id], backref="incoming")


class Source(db.Model):
    __tablename__ = "mis_sources"
    id = db.Column(db.Integer, primary_key=True)
    handle = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    reliability = db.Column(db.String(2), default="F")
    contact_notes = db.Column(db.Text, default="")
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TimelineEntry(db.Model):
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
    source_reliability = db.Column(db.String(2), default="F")
    info_confidence = db.Column(db.String(2), default="6")
    status = db.Column(db.String(20), default="UNVERIFIED")
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
    kind = db.Column(db.String(20), default="IMAGE")
    filename = db.Column(db.String(255))
    mimetype = db.Column(db.String(120), default="application/octet-stream")
    description = db.Column(db.Text, default="")
    source_notes = db.Column(db.Text, default="")
    classification = db.Column(db.String(40), default="SECRET")
    is_original = db.Column(db.Boolean, default=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("mis_media.id"), nullable=True)
    derived_note = db.Column(db.Text, default="")
    data = db.Column(db.LargeBinary)
    sha256 = db.Column(db.String(64), index=True)
    encrypted = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AnalystNote(db.Model):
    __tablename__ = "mis_analyst"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    category = db.Column(db.String(40), default="FACT")
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, default="")
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
            return "OPEN"
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
# AUTO-MIGRATION
# ============================================================
MIGRATIONS = {
    "mis_users": [
        ("codename", "VARCHAR(80) DEFAULT ''"),
        ("clearance", "VARCHAR(40) DEFAULT 'SECRET'"),
    ],
    "mis_cases": [
        ("subject", "VARCHAR(200) DEFAULT ''"),
        ("notes", "TEXT DEFAULT ''"),
        ("legal_note", "TEXT DEFAULT ''"),
        ("threat_level", "VARCHAR(20) DEFAULT 'MEDIUM'"),
        ("classification", "VARCHAR(40) DEFAULT 'SECRET'"),
        ("priority", "INTEGER DEFAULT 3"),
        ("due_date", "TIMESTAMP"),
    ],
    "mis_entities": [
        ("threat_level", "VARCHAR(20) DEFAULT 'LOW'"),
        ("region", "VARCHAR(120) DEFAULT ''"),
        ("latitude", "DOUBLE PRECISION DEFAULT 0"),
        ("longitude", "DOUBLE PRECISION DEFAULT 0"),
    ],
    "mis_intel": [
        ("timeline_id", "INTEGER"),
        ("source_id", "INTEGER"),
        ("category", "VARCHAR(40) DEFAULT 'OBSERVATION'"),
        ("classification", "VARCHAR(40) DEFAULT 'SECRET'"),
        ("source_reliability", "VARCHAR(2) DEFAULT 'F'"),
        ("info_confidence", "VARCHAR(2) DEFAULT '6'"),
        ("status", "VARCHAR(20) DEFAULT 'UNVERIFIED'"),
        ("is_fact", "BOOLEAN DEFAULT FALSE"),
        ("is_claim", "BOOLEAN DEFAULT FALSE"),
        ("analyst_comment", "TEXT DEFAULT ''"),
        ("created_by", "VARCHAR(80) DEFAULT 'system'"),
    ],
    "mis_media": [
        ("timeline_id", "INTEGER"),
        ("kind", "VARCHAR(20) DEFAULT 'IMAGE'"),
        ("description", "TEXT DEFAULT ''"),
        ("source_notes", "TEXT DEFAULT ''"),
        ("classification", "VARCHAR(40) DEFAULT 'SECRET'"),
        ("is_original", "BOOLEAN DEFAULT TRUE"),
        ("parent_id", "INTEGER"),
        ("derived_note", "TEXT DEFAULT ''"),
        ("encrypted", "BOOLEAN DEFAULT FALSE"),
        ("created_by", "VARCHAR(80) DEFAULT 'system'"),
    ],
    "mis_timeline": [
        ("category", "VARCHAR(40) DEFAULT 'OBSERVATION'"),
        ("classification", "VARCHAR(40) DEFAULT 'SECRET'"),
        ("created_by", "VARCHAR(80) DEFAULT 'system'"),
    ],
    "mis_sources": [
        ("reliability", "VARCHAR(2) DEFAULT 'F'"),
        ("description", "TEXT DEFAULT ''"),
        ("contact_notes", "TEXT DEFAULT ''"),
        ("case_id", "INTEGER"),
    ],
    "mis_analyst": [
        ("linked_intel_ids", "VARCHAR(500) DEFAULT ''"),
        ("created_by", "VARCHAR(80) DEFAULT 'system'"),
    ],
    "mis_dead_drops": [
        ("classification", "VARCHAR(40) DEFAULT 'TOP_SECRET'"),
        ("created_by", "VARCHAR(80) DEFAULT 'system'"),
    ],
    "mis_relationships": [
        ("description", "TEXT DEFAULT ''"),
        ("status", "VARCHAR(20) DEFAULT 'UNVERIFIED'"),
        ("case_id", "INTEGER"),
    ],
    "mis_case_entities": [
        ("role", "VARCHAR(80) DEFAULT 'Person'"),
    ],
}


def auto_migrate():
    insp = inspect(db.engine)
    existing_tables = set(insp.get_table_names())
    for table, cols in MIGRATIONS.items():
        if table not in existing_tables:
            continue
        existing_cols = {c["name"] for c in insp.get_columns(table)}
        for col_name, col_type in cols:
            if col_name in existing_cols:
                continue
            try:
                with db.engine.begin() as conn:
                    conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {col_name} {col_type}'))
                print(f"🛠  Migrated: {table}.{col_name}")
            except Exception as e:
                print(f"⚠️  Migration failed {table}.{col_name}: {e}")


# ============================================================
# FORMS
# ============================================================
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 80)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class ChangePasswordForm(FlaskForm):
    current = PasswordField("Current Password", validators=[DataRequired()])
    new = PasswordField("New Password", validators=[DataRequired(), Length(min=10)])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("new")])
    submit = SubmitField("Update Password")


class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    codename = StringField("Display name", validators=[Optional(), Length(0, 80)])
    clearance = SelectField("Role", choices=[
        ("SECRET", "User"), ("TOP_SECRET", "Manager"), ("EYES_ONLY", "Admin")
    ])
    submit = SubmitField("Create User")


class CaseForm(FlaskForm):
    title = StringField("Case name", validators=[DataRequired(), Length(1, 200)])
    subject = StringField("Who/what is this about?", validators=[Optional(), Length(0, 200)])
    notes = TextAreaField("Notes")
    status = SelectField("Status", choices=[
        ("Active", "Active"), ("Paused", "Paused"),
        ("Closed", "Closed"), ("Archived", "Archived")
    ])
    priority = SelectField("Priority", coerce=int, choices=[
        (1, "1 — Very important"), (2, "2 — Important"),
        (3, "3 — Normal"), (4, "4 — Low")
    ])
    due_date = DateTimeField("Reminder date (optional) — YYYY-MM-DD HH:MM",
                             format="%Y-%m-%d %H:%M", validators=[Optional()])
    submit = SubmitField("Save")


class QuickAddForm(FlaskForm):
    """The one box."""
    body = TextAreaField("What did you learn?", validators=[Optional()])
    case_id = SelectField("About", coerce=int, validators=[DataRequired()])
    happened_at = DateTimeField("When", format="%Y-%m-%d %H:%M", validators=[Optional()])
    photos = FileField("Photos")
    voice = FileField("Voice")
    submit = SubmitField("Save")


class UpdateForm(FlaskForm):
    body = TextAreaField("What did you learn?", validators=[Optional()])
    happened_at = DateTimeField("When", format="%Y-%m-%d %H:%M", validators=[DataRequired()])
    photos = FileField("Add photos")
    voice = FileField("Add voice")
    submit = SubmitField("Save Changes")


class EntityForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(1, 200)])
    type = SelectField("Type", choices=[
        ("Person", "Person"), ("Place", "Place"), ("Organisation", "Organisation"),
        ("Vehicle", "Vehicle"), ("Event", "Event"), ("Other", "Other")
    ])
    notes = TextAreaField("Notes")
    region = StringField("Region (optional)", validators=[Optional(), Length(0, 120)])
    submit = SubmitField("Save")


class RelationshipForm(FlaskForm):
    from_id = SelectField("From", coerce=int, validators=[DataRequired()])
    to_id = SelectField("To", coerce=int, validators=[DataRequired()])
    relation = SelectField("How they are connected", choices=[
        ("knows", "knows"), ("family of", "family of"), ("works for", "works for"),
        ("member of", "member of"), ("owns", "owns"), ("lives at", "lives at"),
        ("met with", "met with"), ("communicates with", "communicates with"),
        ("seen with", "seen with"), ("other", "other"),
    ])
    description = TextAreaField("Details")
    submit = SubmitField("Save")


class SourceForm(FlaskForm):
    handle = StringField("Contact name", validators=[DataRequired(), Length(1, 120)])
    description = TextAreaField("Who is this?")
    submit = SubmitField("Save")


class DeadDropForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    body = TextAreaField("Message", validators=[DataRequired()])
    unlock_at = DateTimeField("Open on — YYYY-MM-DD HH:MM",
                              format="%Y-%m-%d %H:%M", validators=[DataRequired()])
    submit = SubmitField("Lock it")


class ReportForm(FlaskForm):
    password = PasswordField("Encryption password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Download encrypted PDF")


# ============================================================
# HELPERS
# ============================================================
def case_choices(current_user_cases=None):
    rows = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    return [(c.id, c.title) for c in rows]


def entity_choices():
    rows = db.session.execute(db.select(Entity).order_by(Entity.name)).scalars().all()
    return [(e.id, f"{e.name} ({e.type})") for e in rows]


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def parse_dt(s):
    if not s:
        return None
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%d %H:%M")
    except Exception:
        try:
            return datetime.strptime(s.strip(), "%Y-%m-%dT%H:%M")
        except Exception:
            return None


# ============================================================
# PDF BUILDER
# ============================================================
def build_case_pdf(case: Case) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=1.8 * cm, rightMargin=1.8 * cm,
                            topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                            title=f"MIS Report — {case.title}")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], textColor=colors.HexColor("#1f3a8a"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#1f3a8a"))
    body = styles["BodyText"]

    story = []
    story.append(Paragraph("MIS CASE FILE", h1))
    story.append(Paragraph(case.title, h2))
    if case.subject:
        story.append(Paragraph(f"About: {case.subject}", body))
    story.append(Paragraph(f"Status: {case.status}", body))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", body))
    story.append(Spacer(1, 0.4 * cm))

    if case.notes:
        story.append(Paragraph("Notes", h2))
        story.append(Paragraph((case.notes or "").replace("\n", "<br/>"), body))
        story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("History", h2))
    updates = sorted(case.updates, key=lambda u: u.happened_at, reverse=True)
    if updates:
        for u in updates:
            story.append(Paragraph(u.happened_at.strftime("%Y-%m-%d %H:%M"), h2))
            if u.body:
                story.append(Paragraph(u.body.replace("\n", "<br/>"), body))
            for p in u.photos:
                story.append(Paragraph(f"[{p.kind.upper()}] {p.filename} · sha256 {(p.sha256 or '')[:16]}…", body))
            story.append(Spacer(1, 0.2 * cm))
    else:
        story.append(Paragraph("— none —", body))

    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("People & Places on this case", h2))
    if case.links:
        for link in case.links:
            story.append(Paragraph(f"<b>{link.entity.name}</b> ({link.entity.type})", body))
    else:
        story.append(Paragraph("— none —", body))

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

    story = [Paragraph("MIS BRIEFING", h1),
             Paragraph(f"Last {days} day(s) · {datetime.utcnow().isoformat()}Z", body),
             Spacer(1, 0.4 * cm)]

    ups = db.session.execute(
        db.select(Update).where(Update.happened_at >= since)
        .order_by(Update.happened_at.desc())
    ).scalars().all()
    story.append(Paragraph(f"News ({len(ups)})", h2))
    for u in ups:
        c = db.session.get(Case, u.case_id)
        story.append(Paragraph(
            f"<b>{u.happened_at.strftime('%Y-%m-%d %H:%M')} · {c.title if c else '—'}</b>", body))
        story.append(Paragraph((u.body or "").replace("\n", "<br/>"), body))
        for p in u.photos:
            story.append(Paragraph(f"[{p.kind.upper()}] {p.filename}", body))
        story.append(Spacer(1, 0.15 * cm))

    doc.build(story)
    return buf.getvalue()


# ============================================================
# ENCRYPTION
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
        flash("Wrong username or password.", "error")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current.data):
            flash("Current password is wrong.", "error")
        else:
            current_user.set_password(form.new.data)
            db.session.commit()
            flash("Password changed.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html", form=form)


# ============================================================
# ROUTES — HOME (with quick add)
# ============================================================
@app.route("/dashboard")
@login_required
def dashboard():
    cases = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    # Recent updates feed
    recent = db.session.execute(
        db.select(Update).order_by(Update.happened_at.desc()).limit(20)
    ).scalars().all()
    return render_template(
        "dashboard.html",
        cases=cases,
        recent=recent,
        case_choices=case_choices()
    )


# ============================================================
# ROUTES — QUICK ADD (the one box)
# ============================================================
@app.route("/add", methods=["POST"])
@login_required
def quick_add():
    form = QuickAddForm()
    form.case_id.choices = case_choices()
    if not form.case_id.data or form.case_id.data == 0:
        flash("Please choose which case this is about.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    body = (form.body.data or "").strip()
    when = form.happened_at.data or datetime.utcnow()

    # Collect files
    photos = []
    if "photos" in request.files:
        for f in request.files.getlist("photos"):
            if f and f.filename:
                photos.append(("photo", f))
    if "voice" in request.files:
        f = request.files.get("voice")
        if f and f.filename:
            photos.append(("voice", f))

    if not body and not photos:
        flash("Type something or add a photo/voice.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    if not body and photos:
        body = f"[{photos[0][0].capitalize()} added]"

    u = Update(case_id=form.case_id.data, body=body, happened_at=when,
               created_by=current_user.username)
    db.session.add(u)
    db.session.flush()

    for kind, f in photos:
        raw = f.read()
        if not raw:
            continue
        um = UpdateMedia(
            update_id=u.id, kind=kind,
            filename=secure_filename(f.filename),
            mimetype=f.mimetype or "application/octet-stream",
            data=raw, sha256=sha256_bytes(raw),
        )
        db.session.add(um)

    db.session.commit()
    audit("update_add", f"Case #{u.case_id}: {body[:40]}", actor=current_user.username)
    flash("Saved.", "success")
    return redirect(request.referrer or url_for("dashboard"))


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
            notes=form.notes.data or "",
            status=form.status.data,
            priority=form.priority.data or 3,
            due_date=form.due_date.data,
        )
        db.session.add(c)
        db.session.commit()
        audit("case_create", c.title, actor=current_user.username)
        flash("Case created.", "success")
        return redirect(url_for("case_detail", cid=c.id))
    rows = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    return render_template("cases.html", form=form, cases=rows)


@app.route("/cases/<int:cid>", methods=["GET", "POST"])
@login_required
def case_detail(cid):
    c = db.session.get(Case, cid) or abort(404)
    form = CaseForm(obj=c)
    if form.validate_on_submit():
        c.title = form.title.data
        c.subject = form.subject.data or ""
        c.notes = form.notes.data or ""
        c.status = form.status.data
        c.priority = form.priority.data or c.priority
        c.due_date = form.due_date.data
        db.session.commit()
        flash("Case updated.", "success")
        return redirect(url_for("case_detail", cid=c.id))

    # entity form for "add person/place"
    entity_form = EntityForm()
    rel_form = RelationshipForm()
    rel_form.from_id.choices = entity_choices()
    rel_form.to_id.choices = entity_choices()

    return render_template(
        "case_detail.html",
        case=c, form=form,
        entity_form=entity_form,
        rel_form=rel_form,
        case_choices=case_choices(),
    )


@app.route("/cases/<int:cid>/delete", methods=["POST"])
@login_required
def case_delete(cid):
    c = db.session.get(Case, cid) or abort(404)
    db.session.delete(c)
    db.session.commit()
    flash("Case deleted.", "success")
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
    fname = f"MIS_{c.title.replace(' ', '_')}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.mpcenc"
    return send_file(io.BytesIO(encrypted), mimetype="application/octet-stream",
                     as_attachment=True, download_name=fname)


# ============================================================
# ROUTES — UPDATE EDIT / DELETE
# ============================================================
@app.route("/updates/<int:uid>/edit", methods=["GET", "POST"])
@login_required
def update_edit(uid):
    u = db.session.get(Update, uid) or abort(404)
    form = UpdateForm(obj=u)
    if form.validate_on_submit():
        u.body = (form.body.data or "").strip() or u.body
        u.happened_at = form.happened_at.data
        # add new files if any
        for kind, key in [("photo", "photos"), ("voice", "voice")]:
            if key in request.files:
                files = request.files.getlist(key) if key == "photos" else [request.files.get(key)]
                for f in files:
                    if f and f.filename:
                        raw = f.read()
                        if raw:
                            db.session.add(UpdateMedia(
                                update_id=u.id, kind=kind,
                                filename=secure_filename(f.filename),
                                mimetype=f.mimetype or "application/octet-stream",
                                data=raw, sha256=sha256_bytes(raw),
                            ))
        db.session.commit()
        flash("Updated.", "success")
        return redirect(url_for("case_detail", cid=u.case_id))
    return render_template("update_edit.html", form=form, update=u)


@app.route("/updates/<int:uid>/delete", methods=["POST"])
@login_required
def update_delete(uid):
    u = db.session.get(Update, uid) or abort(404)
    cid = u.case_id
    db.session.delete(u)
    db.session.commit()
    flash("Deleted.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/updates/<int:uid>/media/<int:mid>/delete", methods=["POST"])
@login_required
def update_media_delete(uid, mid):
    m = db.session.get(UpdateMedia, mid) or abort(404)
    if m.update_id != uid:
        abort(404)
    cid = m.update.case_id
    db.session.delete(m)
    db.session.commit()
    return redirect(url_for("case_detail", cid=cid))


@app.route("/media/<int:mid>/view")
@login_required
def media_view(mid):
    m = db.session.get(UpdateMedia, mid) or abort(404)
    return send_file(io.BytesIO(m.data), mimetype=m.mimetype,
                     as_attachment=False, download_name=m.filename)


# ============================================================
# ROUTES — PEOPLE & PLACES
# ============================================================
@app.route("/entities", methods=["GET", "POST"])
@login_required
def entities():
    form = EntityForm()
    if form.validate_on_submit():
        e = Entity(name=form.name.data, type=form.type.data,
                   notes=form.notes.data or "", region=form.region.data or "")
        db.session.add(e)
        db.session.commit()
        flash("Saved.", "success")
        return redirect(url_for("entities"))
    rows = db.session.execute(db.select(Entity).order_by(Entity.name)).scalars().all()
    return render_template("people.html", form=form, people=rows)


@app.route("/entities/<int:eid>")
@login_required
def entity_detail(eid):
    e = db.session.get(Entity, eid) or abort(404)
    cases = db.session.execute(
        db.select(CaseEntity).where(CaseEntity.entity_id == eid)
    ).scalars().all()
    return render_template("person_detail.html", entity=e, cases=cases)


@app.route("/entities/<int:eid>/delete", methods=["POST"])
@login_required
def entity_delete(eid):
    e = db.session.get(Entity, eid) or abort(404)
    db.session.delete(e)
    db.session.commit()
    return redirect(url_for("entities"))


@app.route("/cases/<int:cid>/entities", methods=["POST"])
@login_required
def case_entity_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    name = (request.form.get("name") or "").strip()
    etype = request.form.get("type") or "Person"
    if name:
        e = Entity(name=name, type=etype)
        db.session.add(e)
        db.session.flush()
        db.session.add(CaseEntity(case_id=c.id, entity_id=e.id, role=etype))
        db.session.commit()
        flash("Added.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/case-entities/<int:link_id>/delete", methods=["POST"])
@login_required
def case_entity_delete(link_id):
    link = db.session.get(CaseEntity, link_id) or abort(404)
    cid = link.case_id
    db.session.delete(link)
    db.session.commit()
    return redirect(url_for("case_detail", cid=cid))


@app.route("/link-entity", methods=["POST"])
@login_required
def link_entity():
    """Attach existing entity to case."""
    cid = request.form.get("case_id", type=int)
    eid = request.form.get("entity_id", type=int)
    if cid and eid:
        if not db.session.execute(
            db.select(CaseEntity).filter_by(case_id=cid, entity_id=eid)
        ).scalar():
            db.session.add(CaseEntity(case_id=cid, entity_id=eid, role="Person"))
            db.session.commit()
    return redirect(url_for("case_detail", cid=cid))


# ============================================================
# ROUTES — RELATIONSHIPS
# ============================================================
@app.route("/who-knows-who", methods=["GET", "POST"])
@login_required
def relationships():
    form = RelationshipForm()
    form.from_id.choices = entity_choices()
    form.to_id.choices = entity_choices()
    if form.validate_on_submit():
        if form.from_id.data == form.to_id.data:
            flash("Cannot link someone to themselves.", "error")
        else:
            r = Relationship(
                from_id=form.from_id.data, to_id=form.to_id.data,
                relation=form.relation.data,
                description=form.description.data or "",
            )
            db.session.add(r)
            db.session.commit()
            flash("Saved.", "success")
            return redirect(url_for("relationships"))
    rows = db.session.execute(
        db.select(Relationship).order_by(Relationship.created_at.desc())
    ).scalars().all()
    return render_template("relationships.html", form=form, relationships=rows)


@app.route("/relationships/<int:rid>/delete", methods=["POST"])
@login_required
def relationship_delete(rid):
    r = db.session.get(Relationship, rid) or abort(404)
    db.session.delete(r)
    db.session.commit()
    return redirect(url_for("relationships"))


# ============================================================
# ROUTES — CONTACTS
# ============================================================
@app.route("/contacts", methods=["GET", "POST"])
@login_required
def contacts():
    form = SourceForm()
    if form.validate_on_submit():
        s = Source(handle=form.handle.data, description=form.description.data or "")
        db.session.add(s)
        db.session.commit()
        flash("Saved.", "success")
        return redirect(url_for("contacts"))
    rows = db.session.execute(db.select(Source).order_by(Source.handle)).scalars().all()
    return render_template("sources.html", form=form, sources=rows)


@app.route("/contacts/<int:sid>/delete", methods=["POST"])
@login_required
def contact_delete(sid):
    s = db.session.get(Source, sid) or abort(404)
    db.session.delete(s)
    db.session.commit()
    return redirect(url_for("contacts"))


# ============================================================
# ROUTES — SEARCH + ACTIVITY
# ============================================================
@app.route("/search")
@login_required
def search():
    q = (request.args.get("q") or "").strip()
    results = {"cases": [], "updates": [], "entities": []}
    if q:
        like = f"%{q}%"
        results["cases"] = db.session.execute(
            db.select(Case).where(or_(Case.title.ilike(like), Case.subject.ilike(like), Case.notes.ilike(like)))
        ).scalars().all()
        results["updates"] = db.session.execute(
            db.select(Update).where(Update.body.ilike(like)).order_by(Update.happened_at.desc())
        ).scalars().all()
        results["entities"] = db.session.execute(
            db.select(Entity).where(or_(Entity.name.ilike(like), Entity.notes.ilike(like)))
        ).scalars().all()
    return render_template("search.html", q=q, results=results)


@app.route("/activity")
@login_required
def activity():
    rows = db.session.execute(
        db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(300)
    ).scalars().all()
    return render_template("audit.html", entries=rows)


# ============================================================
# ROUTES — TIME-LOCKED NOTES
# ============================================================
@app.route("/timed-notes", methods=["GET", "POST"])
@login_required
def drops():
    form = DeadDropForm()
    if form.validate_on_submit():
        d = DeadDrop(title=form.title.data, body=form.body.data,
                     unlock_at=form.unlock_at.data, created_by=current_user.username)
        db.session.add(d)
        db.session.commit()
        flash("Locked.", "success")
        return redirect(url_for("drops"))
    rows = db.session.execute(db.select(DeadDrop).order_by(DeadDrop.unlock_at)).scalars().all()
    return render_template("drops.html", form=form, drops=rows)


@app.route("/timed-notes/<int:did>/delete", methods=["POST"])
@login_required
def drop_delete(did):
    d = db.session.get(DeadDrop, did) or abort(404)
    db.session.delete(d)
    db.session.commit()
    return redirect(url_for("drops"))


# ============================================================
# ROUTES — BRIEFING
# ============================================================
@app.route("/briefing")
@login_required
def briefing():
    days = int(request.args.get("days", 1))
    since = datetime.utcnow() - timedelta(days=days)
    updates = db.session.execute(
        db.select(Update).where(Update.happened_at >= since)
        .order_by(Update.happened_at.desc())
    ).scalars().all()
    return render_template("briefing.html", days=days, since=since, updates=updates)


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
    fname = f"MIS_Briefing_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.mpcenc"
    return send_file(io.BytesIO(encrypted), mimetype="application/octet-stream",
                     as_attachment=True, download_name=fname)


# ============================================================
# ROUTES — USERS
# ============================================================
@app.route("/users", methods=["GET", "POST"])
@login_required
def users():
    form = UserForm()
    if form.validate_on_submit():
        uname = form.username.data.strip()
        if db.session.execute(db.select(User).filter_by(username=uname)).scalar():
            flash("Username already taken.", "error")
        else:
            u = User(username=uname, codename=form.codename.data or "",
                     clearance=form.clearance.data)
            u.set_password(form.password.data)
            db.session.add(u)
            db.session.commit()
            flash("User created.", "success")
            return redirect(url_for("users"))
    rows = db.session.execute(db.select(User).order_by(User.created_at)).scalars().all()
    return render_template("agents.html", form=form, agents=rows)


@app.route("/users/<int:uid>/delete", methods=["POST"])
@login_required
def user_delete(uid):
    if uid == current_user.id:
        flash("You cannot delete yourself.", "error")
        return redirect(url_for("users"))
    u = db.session.get(User, uid) or abort(404)
    db.session.delete(u)
    db.session.commit()
    return redirect(url_for("users"))


# ============================================================
# BOOTSTRAP
# ============================================================
def bootstrap():
    with app.app_context():
        db.create_all()
        auto_migrate()

        u = app.config["INITIAL_USERNAME"]
        p = app.config["INITIAL_PASSWORD"]
        force = os.getenv("FORCE_SEED", "0") == "1"

        existing = db.session.execute(db.select(User).filter_by(username=u)).scalar()

        if force:
            User.query.delete()
            db.session.commit()
            user = User(username=u, codename="Admin", clearance="EYES_ONLY")
            user.set_password(p)
            db.session.add(user)
            db.session.commit()
            print(f"🔥 Force-reseeded user: {u}")
            return

        if not existing:
            user = User(username=u, codename="Admin", clearance="EYES_ONLY")
            user.set_password(p)
            db.session.add(user)
            db.session.commit()
            print(f"✅ Seeded user: {u}")
        else:
            print(f"✅ User {u} OK")


bootstrap()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
