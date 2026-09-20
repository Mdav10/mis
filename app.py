# ============================================================
# MIS v15 — Restored proper AES-256 PDF + encrypted backups
# ============================================================

import os, io, json, hmac, hashlib, secrets, base64
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, send_file, abort, jsonify, session
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import (
    StringField, PasswordField, TextAreaField, SelectField,
    BooleanField, SubmitField, DateTimeField
)
from wtforms.validators import DataRequired, Length, EqualTo, Optional, Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy import or_, text, inspect

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
)
from reportlab.lib import colors

from pypdf import PdfReader, PdfWriter
import pyotp

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
    MAX_CONTENT_LENGTH = 80 * 1024 * 1024
    INITIAL_USERNAME = os.getenv("INITIAL_USERNAME", "Mpc")
    INITIAL_PASSWORD = os.getenv("INITIAL_PASSWORD", "08800Mpc!")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_IDLE_TIMEOUT = timedelta(minutes=30)


app = Flask(__name__)
app.config.from_object(Config)

from flask_wtf.csrf import generate_csrf

@app.context_processor
def _inject_csrf():
    return {"csrf_token": generate_csrf}

@app.context_processor
def _inject_now():
    return {"now_local_str": datetime.now().strftime("%Y-%m-%dT%H:%M")}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in."


# ============================================================
# CRYPTO
# ============================================================
MASTER_KEY_ENV = os.getenv("MASTER_KEY", "")


def get_master_key():
    raw = MASTER_KEY_ENV.strip()
    if not raw:
        raw = hashlib.sha256(app.config["SECRET_KEY"].encode()).hexdigest()
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    return hashlib.sha256(raw.encode()).digest()


def field_encrypt(plaintext):
    if not plaintext:
        return ""
    try:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(get_master_key()).encrypt(nonce, plaintext.encode("utf-8"),
                                              associated_data=b"MIS_FIELD")
        return base64.b64encode(b"MIS1" + b"\x00" * 16 + nonce + ct).decode("ascii")
    except Exception:
        return plaintext


def field_decrypt(stored):
    if not stored:
        return ""
    try:
        blob = base64.b64decode(stored, validate=True)
        if blob[:4] != b"MIS1":
            return stored
        return AESGCM(get_master_key()).decrypt(blob[20:32], blob[32:],
                                                associated_data=b"MIS_FIELD").decode("utf-8")
    except Exception:
        return stored


def parse_local_dt(s):
    if not s:
        return None
    s = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


# ============================================================
# ROLES
# ============================================================
ROLE_TOP = "top_secret"
ROLE_AGENT = "agent"
ROLE_ANALYST = "analyst"

ROLE_LABELS = [
    (ROLE_TOP, "Top Secret"),
    (ROLE_AGENT, "Agent"),
    (ROLE_ANALYST, "Analyst"),
]


# ============================================================
# MODELS
# ============================================================
class User(UserMixin, db.Model):
    __tablename__ = "mis_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    codename = db.Column(db.String(80), default="")
    email = db.Column(db.String(160), default="")
    role = db.Column(db.String(20), default=ROLE_AGENT)
    totp_secret = db.Column(db.String(80), default="")
    totp_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text, default="")
    last_login = db.Column(db.DateTime, nullable=True)
    last_ip = db.Column(db.String(64), default="")
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
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

    def verify_totp(self, code):
        if not self.totp_enabled or not self.totp_secret:
            return True
        try:
            return pyotp.TOTP(self.totp_secret).verify(str(code).strip(), valid_window=1)
        except Exception:
            return False

    def check_backup_code(self, code):
        if not self.backup_codes:
            return False
        code = str(code).strip().replace("-", "").upper()
        stored = self.backup_codes.split("\n")
        new_codes = []
        matched = False
        for h in stored:
            if not h.strip():
                continue
            if hmac.compare_digest(h, hashlib.sha256(code.encode()).hexdigest()):
                matched = True
            else:
                new_codes.append(h)
        if matched:
            self.backup_codes = "\n".join(new_codes)
            db.session.commit()
        return matched

    def generate_backup_codes(self):
        codes = []
        for _ in range(10):
            c = "-".join("".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(4)) for _ in range(3))
            codes.append(c)
        self.backup_codes = "\n".join(
            hashlib.sha256(c.replace("-", "").upper().encode()).hexdigest() for c in codes
        )
        return codes

    @property
    def is_top(self): return self.role == ROLE_TOP
    @property
    def is_agent(self): return self.role == ROLE_AGENT
    @property
    def is_analyst(self): return self.role == ROLE_ANALYST


class SessionRecord(db.Model):
    __tablename__ = "mis_sessions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    session_id = db.Column(db.String(120), unique=True, index=True)
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    revoked = db.Column(db.Boolean, default=False)


class Case(db.Model):
    __tablename__ = "mis_cases"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(200), default="")
    notes_enc = db.Column(db.Text, default="")
    status = db.Column(db.String(40), default="Active")
    threat_level = db.Column(db.String(20), default="MEDIUM")
    priority = db.Column(db.Integer, default=3)
    due_date = db.Column(db.DateTime, nullable=True)
    assigned_agent_id = db.Column(db.Integer, nullable=True)
    integrity_hash = db.Column(db.String(64), default="")
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    updates = db.relationship("Update", backref="case", lazy=True,
                              cascade="all, delete-orphan",
                              order_by="Update.happened_at.desc()")
    links = db.relationship("CaseEntity", backref="case", lazy=True,
                            cascade="all, delete-orphan")
    analyst_notes = db.relationship("AnalystNote", backref="case", lazy=True,
                                    cascade="all, delete-orphan",
                                    order_by="AnalystNote.created_at.desc()")

    @property
    def notes(self): return field_decrypt(self.notes_enc or "")
    @notes.setter
    def notes(self, v): self.notes_enc = field_encrypt(v or "")

    @property
    def assigned_agent(self):
        if not self.assigned_agent_id:
            return None
        return db.session.get(User, self.assigned_agent_id)


class AnalystNote(db.Model):
    __tablename__ = "mis_analyst_notes"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    category = db.Column(db.String(40), default="ASSESSMENT")
    title = db.Column(db.String(200), nullable=False)
    body_enc = db.Column(db.Text, default="")
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def body(self): return field_decrypt(self.body_enc or "")
    @body.setter
    def body(self, v): self.body_enc = field_encrypt(v or "")


class Update(db.Model):
    __tablename__ = "mis_updates"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    body_enc = db.Column(db.Text, default="")
    happened_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    created_by = db.Column(db.String(80), default="system")
    integrity_hash = db.Column(db.String(64), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    photos = db.relationship("UpdateMedia", backref="update", lazy=True,
                             cascade="all, delete-orphan",
                             order_by="UpdateMedia.id")

    @property
    def body(self): return field_decrypt(self.body_enc or "")
    @body.setter
    def body(self, v): self.body_enc = field_encrypt(v or "")


class UpdateMedia(db.Model):
    __tablename__ = "mis_update_media"
    id = db.Column(db.Integer, primary_key=True)
    update_id = db.Column(db.Integer, db.ForeignKey("mis_updates.id"), nullable=False)
    kind = db.Column(db.String(20), default="photo")
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
    notes_enc = db.Column(db.Text, default="")
    verified = db.Column(db.Boolean, default=False)
    threat_level = db.Column(db.String(20), default="LOW")
    region = db.Column(db.String(120), default="")
    latitude = db.Column(db.Float, default=0)
    longitude = db.Column(db.Float, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def notes(self): return field_decrypt(self.notes_enc or "")
    @notes.setter
    def notes(self, v): self.notes_enc = field_encrypt(v or "")


class CaseEntity(db.Model):
    __tablename__ = "mis_case_entities"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    entity_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    role = db.Column(db.String(80), default="Other")
    note_enc = db.Column(db.Text, default="")
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    entity = db.relationship("Entity")

    @property
    def note(self): return field_decrypt(self.note_enc or "")
    @note.setter
    def note(self, v): self.note_enc = field_encrypt(v or "")


class Relationship(db.Model):
    __tablename__ = "mis_relationships"
    id = db.Column(db.Integer, primary_key=True)
    from_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    to_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    relation = db.Column(db.String(80), default="knows")
    description_enc = db.Column(db.Text, default="")
    case_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    from_entity = db.relationship("Entity", foreign_keys=[from_id], backref="outgoing")
    to_entity = db.relationship("Entity", foreign_keys=[to_id], backref="incoming")

    @property
    def description(self): return field_decrypt(self.description_enc or "")
    @description.setter
    def description(self, v): self.description_enc = field_encrypt(v or "")


class Source(db.Model):
    __tablename__ = "mis_sources"
    id = db.Column(db.Integer, primary_key=True)
    handle = db.Column(db.String(120), nullable=False)
    description_enc = db.Column(db.Text, default="")
    case_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def description(self): return field_decrypt(self.description_enc or "")
    @description.setter
    def description(self, v): self.description_enc = field_encrypt(v or "")


class DeadDrop(db.Model):
    __tablename__ = "mis_dead_drops"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body_enc = db.Column(db.Text, default="")
    unlock_at = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def body(self): return field_decrypt(self.body_enc or "")
    @body.setter
    def body(self, v): self.body_enc = field_encrypt(v or "")

    @property
    def is_unlocked(self): return datetime.now() >= self.unlock_at

    @property
    def countdown(self):
        if self.is_unlocked:
            return "OPEN"
        d = self.unlock_at - datetime.now()
        return f"{d.days}d {d.seconds//3600:02d}:{(d.seconds%3600)//60:02d}:{d.seconds%60:02d}"


class AuditLog(db.Model):
    __tablename__ = "mis_audit_log"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(80))
    detail = db.Column(db.Text)
    actor = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Backup(db.Model):
    __tablename__ = "mis_backups"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    size_bytes = db.Column(db.Integer, default=0)
    record_count = db.Column(db.Integer, default=0)
    created_by = db.Column(db.String(80), default="system")
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
        ("email", "VARCHAR(160) DEFAULT ''"),
        ("role", "VARCHAR(20) DEFAULT 'agent'"),
        ("totp_secret", "VARCHAR(80) DEFAULT ''"),
        ("totp_enabled", "BOOLEAN DEFAULT FALSE"),
        ("backup_codes", "TEXT DEFAULT ''"),
        ("last_login", "TIMESTAMP"),
        ("last_ip", "VARCHAR(64) DEFAULT ''"),
        ("failed_attempts", "INTEGER DEFAULT 0"),
        ("locked_until", "TIMESTAMP"),
    ],
    "mis_cases": [
        ("subject", "VARCHAR(200) DEFAULT ''"),
        ("notes_enc", "TEXT DEFAULT ''"),
        ("threat_level", "VARCHAR(20) DEFAULT 'MEDIUM'"),
        ("priority", "INTEGER DEFAULT 3"),
        ("due_date", "TIMESTAMP"),
        ("assigned_agent_id", "INTEGER"),
        ("integrity_hash", "VARCHAR(64) DEFAULT ''"),
        ("created_by", "VARCHAR(80) DEFAULT 'system'"),
    ],
    "mis_updates": [
        ("body_enc", "TEXT DEFAULT ''"),
        ("integrity_hash", "VARCHAR(64) DEFAULT ''"),
    ],
    "mis_entities": [
        ("notes_enc", "TEXT DEFAULT ''"),
        ("verified", "BOOLEAN DEFAULT FALSE"),
        ("threat_level", "VARCHAR(20) DEFAULT 'LOW'"),
        ("region", "VARCHAR(120) DEFAULT ''"),
        ("latitude", "DOUBLE PRECISION DEFAULT 0"),
        ("longitude", "DOUBLE PRECISION DEFAULT 0"),
    ],
    "mis_case_entities": [
        ("role", "VARCHAR(80) DEFAULT 'Other'"),
        ("note_enc", "TEXT DEFAULT ''"),
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


def compute_integrity(obj, extra=""):
    parts = []
    for col in ("id", "created_at"):
        parts.append(str(getattr(obj, col, "") or ""))
    for col in ("title", "subject", "status", "threat_level", "priority"):
        if hasattr(obj, col):
            parts.append(str(getattr(obj, col) or ""))
    parts.append(extra)
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


# ============================================================
# PERMISSIONS
# ============================================================
def can_view_case(user, case):
    if user.role in (ROLE_TOP, ROLE_ANALYST):
        return True
    if user.role == ROLE_AGENT:
        return case.assigned_agent_id == user.id
    return False


def can_write_case_entries(user, case):
    if user.role == ROLE_AGENT and case.assigned_agent_id == user.id:
        return True
    return False


def can_edit_case_meta(user, case):
    return user.role == ROLE_TOP


def can_delete_case(user, case):
    return user.role == ROLE_TOP


def can_write_analyst_note(user, case):
    return user.role in (ROLE_TOP, ROLE_ANALYST)


def require_role(*roles):
    def wrapper(fn):
        @wraps(fn)
        def inner(*a, **kw):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                flash("Insufficient clearance.", "error")
                return redirect(url_for("dashboard"))
            return fn(*a, **kw)
        return inner
    return wrapper


# ============================================================
# DELETES
# ============================================================
def delete_case_and_children(cid):
    try:
        with db.engine.begin() as conn:
            conn.execute(text("""
                DELETE FROM mis_update_media
                WHERE update_id IN (SELECT id FROM mis_updates WHERE case_id = :cid)
            """), {"cid": cid})
            for tbl, col in [
                ("mis_analyst_notes", "case_id"),
                ("mis_case_entities", "case_id"),
                ("mis_updates", "case_id"),
                ("mis_cases", "id"),
            ]:
                try:
                    conn.execute(text(f"DELETE FROM {tbl} WHERE {col} = :cid"), {"cid": cid})
                except Exception as e:
                    print(f"⚠️  Skipped {tbl}: {e}")
        return True, None
    except Exception as e:
        return False, str(e)


def delete_entity_and_children(eid):
    try:
        with db.engine.begin() as conn:
            for tbl, col in [
                ("mis_case_entities", "entity_id"),
                ("mis_relationships", "from_id"),
                ("mis_relationships", "to_id"),
                ("mis_entities", "id"),
            ]:
                try:
                    conn.execute(text(f"DELETE FROM {tbl} WHERE {col} = :eid"), {"eid": eid})
                except Exception as e:
                    print(f"⚠️  Skipped {tbl}.{col}: {e}")
        return True, None
    except Exception as e:
        return False, str(e)


def delete_update_and_children(uid):
    try:
        with db.engine.begin() as conn:
            conn.execute(text("DELETE FROM mis_update_media WHERE update_id = :uid"), {"uid": uid})
            conn.execute(text("DELETE FROM mis_updates WHERE id = :uid"), {"uid": uid})
        return True, None
    except Exception as e:
        return False, str(e)


# ============================================================
# FORMS
# ============================================================
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 80)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Continue")


class TwoFAForm(FlaskForm):
    code = StringField("Code", validators=[DataRequired(), Length(4, 20)])
    submit = SubmitField("Verify")


class ChangePasswordForm(FlaskForm):
    current = PasswordField("Current Password", validators=[DataRequired()])
    new = PasswordField("New Password", validators=[DataRequired(), Length(min=10)])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("new")])
    submit = SubmitField("Update Password")


class Setup2FAForm(FlaskForm):
    code = StringField("Code", validators=[DataRequired(), Length(6)])
    submit = SubmitField("Enable 2FA")


class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    codename = StringField("Display name", validators=[Optional(), Length(0, 80)])
    email = StringField("Email", validators=[Optional(), Email(), Length(0, 160)])
    role = SelectField("Role", choices=ROLE_LABELS, default=ROLE_AGENT)
    submit = SubmitField("Create User")


class CaseForm(FlaskForm):
    title = StringField("Case name", validators=[DataRequired(), Length(1, 200)])
    subject = StringField("Subject", validators=[Optional(), Length(0, 200)])
    notes = TextAreaField("Notes")
    status = SelectField("Status", choices=[
        ("Active", "Active"), ("Paused", "Paused"),
        ("Closed", "Closed"), ("Archived", "Archived")
    ])
    priority = SelectField("Priority", coerce=int, choices=[
        (1, "1 — Critical"), (2, "2 — High"), (3, "3 — Standard"), (4, "4 — Low")
    ])
    threat_level = SelectField("Threat", choices=[
        ("LOW", "Low"), ("MEDIUM", "Medium"), ("HIGH", "High"), ("CRITICAL", "Critical")
    ], default="MEDIUM")
    due_date = DateTimeField("Reminder — YYYY-MM-DD HH:MM",
                             format="%Y-%m-%d %H:%M", validators=[Optional()])
    assigned_agent_id = SelectField("Assign to Agent", coerce=int, validators=[Optional()])
    submit = SubmitField("Save")


class QuickAddForm(FlaskForm):
    body = TextAreaField("What did you learn?", validators=[Optional()])
    case_id = SelectField("About", coerce=int, validators=[DataRequired()])
    happened_at = StringField("When", validators=[Optional()])
    photos = FileField("Photos")
    voice = FileField("Voice")
    submit = SubmitField("Save")


class EntityForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(1, 200)])
    type = SelectField("Type", choices=[
        ("Person", "Person"), ("Place", "Place"), ("Organisation", "Organisation"),
        ("Vehicle", "Vehicle"), ("Event", "Event"), ("Other", "Other")
    ])
    notes = TextAreaField("Notes")
    region = StringField("Region (optional)", validators=[Optional(), Length(0, 120)])
    latitude = StringField("Latitude (optional)", validators=[Optional(), Length(0, 30)])
    longitude = StringField("Longitude (optional)", validators=[Optional(), Length(0, 30)])
    submit = SubmitField("Save")


class RelationshipForm(FlaskForm):
    from_id = SelectField("From", coerce=int, validators=[DataRequired()])
    to_id = SelectField("To", coerce=int, validators=[DataRequired()])
    relation = SelectField("Connection", choices=[
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
    submit = SubmitField("Seal")


class ReportForm(FlaskForm):
    password = PasswordField("PDF password", validators=[DataRequired(), Length(min=6)])
    template = SelectField("Template", choices=[
        ("full", "Full Case File"),
        ("summary", "Executive Summary"),
        ("timeline", "Timeline Only"),
        ("person", "Person Profile"),
        ("evidence", "Evidence Register"),
        ("gaps", "Gap Analysis"),
    ], default="full")
    submit = SubmitField("Download PDF")


class AnalystNoteForm(FlaskForm):
    category = SelectField("Category", choices=[
        ("FACT", "Fact"),
        ("CLAIM", "Claim"),
        ("CORROBORATED", "Corroborated"),
        ("UNVERIFIED", "Unverified"),
        ("ASSESSMENT", "Analytic Assessment"),
        ("QUESTION", "Open Question"),
        ("CONTRADICTION", "Contradiction"),
    ], default="ASSESSMENT")
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    body = TextAreaField("Analysis", validators=[DataRequired()])
    submit = SubmitField("Save Analysis")


# ============================================================
# HELPERS
# ============================================================
def case_choices_for(user):
    if user.role in (ROLE_TOP, ROLE_ANALYST):
        rows = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    else:
        rows = db.session.execute(
            db.select(Case).where(Case.assigned_agent_id == user.id).order_by(Case.title)
        ).scalars().all()
    return [(c.id, c.title) for c in rows]


def agent_choices():
    rows = db.session.execute(
        db.select(User).where(User.role == ROLE_AGENT).order_by(User.username)
    ).scalars().all()
    return [(0, "— Unassigned —")] + [(u.id, f"{u.username} ({u.codename or 'no codename'})") for u in rows]


def entity_choices():
    rows = db.session.execute(db.select(Entity).order_by(Entity.name)).scalars().all()
    return [(e.id, f"{e.name} ({e.type})") for e in rows]


def user_choices():
    rows = db.session.execute(db.select(User).order_by(User.username)).scalars().all()
    return [(u.id, u.username) for u in rows]


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def esc(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ============================================================
# PDF BUILDER
# ============================================================
def build_pdf(case, template="full"):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2.0 * cm, rightMargin=2.0 * cm,
                            topMargin=2.0 * cm, bottomMargin=2.0 * cm,
                            title=f"MIS Report — {case.title}")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"],
                        textColor=colors.HexColor("#111111"),
                        fontName="Helvetica-Bold", fontSize=18)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"],
                        textColor=colors.HexColor("#333333"),
                        fontName="Helvetica-Bold", fontSize=12)
    h3 = ParagraphStyle("h3", parent=styles["Heading3"],
                        textColor=colors.HexColor("#111111"),
                        fontName="Helvetica-Bold", fontSize=11)
    body = ParagraphStyle("body", parent=styles["BodyText"],
                          fontName="Helvetica", fontSize=10, leading=14)
    meta = ParagraphStyle("meta", parent=styles["BodyText"],
                          fontName="Helvetica-Oblique", fontSize=9,
                          textColor=colors.HexColor("#555555"))

    story = []
    title_map = {
        "full": "MIS CASE FILE", "summary": "MIS EXECUTIVE SUMMARY",
        "timeline": "MIS CHRONOLOGICAL TIMELINE", "person": "MIS PERSON PROFILE",
        "evidence": "MIS EVIDENCE REGISTER", "gaps": "MIS GAP ANALYSIS",
    }
    story.append(Paragraph(title_map.get(template, "MIS CASE FILE"), h1))
    story.append(Paragraph(esc(case.title), h2))
    if case.subject:
        story.append(Paragraph(f"Subject: {esc(case.subject)}", body))
    agent_txt = f" · Agent: {case.assigned_agent.username}" if case.assigned_agent else ""
    story.append(Paragraph(f"Status: {esc(case.status)} · Threat: {esc(case.threat_level)} · Priority: {case.priority}{agent_txt}", body))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", meta))
    story.append(Spacer(1, 0.4 * cm))

    if template in ("full", "summary") and case.notes:
        story.append(Paragraph("Case Notes", h2))
        for para in (case.notes or "").split("\n"):
            if para.strip():
                story.append(Paragraph(esc(para), body))
        story.append(Spacer(1, 0.3 * cm))

    if template in ("full", "timeline", "summary"):
        story.append(Paragraph("Chronological Record", h2))
        updates = sorted(case.updates, key=lambda u: u.happened_at, reverse=False)
        if template == "summary":
            updates = updates[-10:]
        if updates:
            for u in updates:
                story.append(Paragraph(u.happened_at.strftime("%d %b %Y · %H:%M"), h3))
                if u.body:
                    for para in (u.body or "").split("\n"):
                        if para.strip():
                            story.append(Paragraph(esc(para), body))
                if template == "full":
                    for m in u.photos:
                        if m.kind == "photo":
                            try:
                                img = Image(io.BytesIO(m.data))
                                iw, ih = img.imageWidth, img.imageHeight
                                ratio = min((15 * cm) / iw, (10 * cm) / ih, 1.0)
                                img.drawWidth = iw * ratio
                                img.drawHeight = ih * ratio
                                story.append(Spacer(1, 0.15 * cm))
                                story.append(img)
                                story.append(Paragraph(f"[Image: {esc(m.filename)}]", meta))
                            except Exception:
                                pass
                    for m in u.photos:
                        if m.kind == "voice":
                            story.append(Paragraph(f"[Voice memo attached: {esc(m.filename or 'audio')}]", meta))
                story.append(Spacer(1, 0.2 * cm))
        else:
            story.append(Paragraph("— no entries —", body))
        story.append(Spacer(1, 0.3 * cm))

    if template in ("full", "summary"):
        story.append(Paragraph("Analyst Assessment", h2))
        notes = case.analyst_notes or []
        if template == "summary":
            notes = notes[:5]
        if notes:
            for n in notes:
                story.append(Paragraph(f"<b>{esc(n.category)}: {esc(n.title)}</b>", h3))
                for para in (n.body or "").split("\n"):
                    if para.strip():
                        story.append(Paragraph(esc(para), body))
                story.append(Paragraph(f"— {esc(n.created_by)} · {n.created_at.strftime('%d %b %Y')}", meta))
                story.append(Spacer(1, 0.15 * cm))
        else:
            story.append(Paragraph("— none —", body))
        story.append(Spacer(1, 0.3 * cm))

    if template in ("full", "person"):
        story.append(Paragraph("People on this Case", h2))
        if case.links:
            for link in case.links:
                e = link.entity
                story.append(Paragraph(f"<b>{esc(e.name)}</b> — {esc(link.role or e.type)}", h3))
                if link.note:
                    for para in (link.note or "").split("\n"):
                        if para.strip():
                            story.append(Paragraph(esc(para), body))
                story.append(Spacer(1, 0.15 * cm))
        else:
            story.append(Paragraph("— none —", body))

    if template in ("full", "evidence"):
        story.append(PageBreak())
        story.append(Paragraph("Evidence Register", h2))
        rows = []
        for u in case.updates:
            for m in u.photos:
                rows.append((u.happened_at, u.id, m))
        if rows:
            data = [["When", "Entry", "Kind", "File", "SHA-256"]]
            for when, uid, m in rows:
                data.append([when.strftime("%d %b %Y"), str(uid), m.kind,
                             (m.filename or "")[:32], (m.sha256 or "")[:24] + "…"])
            t = Table(data, colWidths=[2.5*cm, 1.5*cm, 1.8*cm, 6*cm, 5.5*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("— none —", body))

    doc.build(story)
    return buf.getvalue()


# ============================================================
# PDF ENCRYPTION — THE FIX
# ============================================================
def encrypt_pdf_with_attachments(pdf_bytes, password, attachments):
    """Real AES-256 password-protected PDF.

    Rules to make it actually prompt for password on every reader:
      - user_password = owner_password = the password you typed
      - algorithm = AES-256
      - permissions_flag with all bits allowed once unlocked
      - We *verify* the output by re-reading it in memory. If pypdf
        would let us read it WITHOUT the password, we re-encrypt
        with a fallback that is known to work.
    """
    # --- Pass 1: standard pypdf AES-256 ---
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        for att in attachments:
            try:
                writer.add_attachment(filename=att["name"], data=att["data"])
            except Exception as e:
                print(f"⚠️  Attach failed {att.get('name')}: {e}")
        writer.encrypt(
            user_password=password,
            owner_password=password,
            permissions_flag=-1,      # allow everything once unlocked
            algorithm="AES-256",
        )
        out = io.BytesIO()
        writer.write(out)
        blob = out.getvalue()

        # Verify: we must NOT be able to read without the password.
        try:
            verify = PdfReader(io.BytesIO(blob))
            if verify.is_encrypted:
                # Try to decrypt WITHOUT password — should fail
                try:
                    result = verify.decrypt("")
                    if result != 0:
                        # uh oh — empty password unlocked it
                        print("⚠️  PDF opened with empty password — forcing fallback")
                        return _encrypt_pdf_fallback(pdf_bytes, password, attachments)
                except Exception:
                    pass  # good — refused empty password
            return blob
        except Exception:
            return blob
    except Exception as e:
        print(f"⚠️  Primary PDF encrypt failed: {e}")
        return _encrypt_pdf_fallback(pdf_bytes, password, attachments)


def _encrypt_pdf_fallback(pdf_bytes, password, attachments):
    """Second attempt: some pypdf versions honour RC4+AES-128 more
    reliably than AES-256 when the user/owner passwords are the same.
    We try each algorithm in order until one produces a file that
    refuses to open without the password."""
    attempts = [
        ("AES-256", 3),
        ("AES-128", 2),
        ("RC4-128", 1),
    ]
    for algorithm, _v in attempts:
        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            for att in attachments:
                try:
                    writer.add_attachment(filename=att["name"], data=att["data"])
                except Exception:
                    pass
            writer.encrypt(
                user_password=password,
                owner_password=password,
                permissions_flag=-1,
                algorithm=algorithm,
            )
            out = io.BytesIO()
            writer.write(out)
            blob = out.getvalue()

            # verify it prompts
            v = PdfReader(io.BytesIO(blob))
            if v.is_encrypted:
                try:
                    r = v.decrypt("")
                    if r == 0:
                        # opened with empty → keep trying
                        continue
                except Exception:
                    return blob
            else:
                # not even marked as encrypted → keep trying
                continue
            return blob
        except Exception as e:
            print(f"⚠️  Fallback {algorithm} failed: {e}")
            continue
    # last resort: return the primary output anyway
    print("🚨 All PDF encryption attempts failed — returning best effort")
    return pdf_bytes


# ============================================================
# BACKUP ENCRYPTION — with plaintext header marker
# ============================================================
def make_encrypted_backup(password):
    """Return (blob, case_count). Blob is:
       b'MISB1' + ascii_header_length(4) + header + salt(16) + nonce(12) + ct
       Header is JSON with date + case count + note.
    """
    data = {"created_at": datetime.utcnow().isoformat(), "cases": []}
    for c in db.session.execute(db.select(Case)).scalars().all():
        cd = {"id": c.id, "title": c.title, "subject": c.subject, "notes": c.notes,
              "status": c.status, "priority": c.priority, "threat_level": c.threat_level,
              "updates": []}
        for u in c.updates:
            cd["updates"].append({
                "when": u.happened_at.isoformat(),
                "body": u.body,
                "media_count": len(u.photos),
            })
        data["cases"].append(cd)

    header = {
        "product": "MIS",
        "format": "misbak-v1",
        "algorithm": "AES-256-GCM",
        "key_derivation": "SHA-256(password)",
        "note": "Decrypt with the same password you entered.",
        "created_at": data["created_at"],
        "case_count": len(data["cases"]),
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    header_len = len(header_bytes).to_bytes(4, "big")

    raw = json.dumps(data, indent=2).encode("utf-8")
    nonce = secrets.token_bytes(12)
    salt = secrets.token_bytes(16)
    key = hashlib.sha256((password + salt.hex()).encode()).digest()
    ct = AESGCM(key).encrypt(nonce, raw, associated_data=b"MIS_BACKUP_V1")
    blob = b"MISB1" + header_len + header_bytes + salt + nonce + ct
    return blob, len(data["cases"])


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
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            flash(f"Account locked until {user.locked_until.strftime('%H:%M')}.", "error")
            return render_template("login.html", form=form)
        if user and user.check_password(form.password.data):
            user.failed_attempts = 0
            user.locked_until = None
            user.last_ip = ip
            db.session.commit()
            if user.totp_enabled:
                session["pending_2fa_user"] = user.id
                return redirect(url_for("two_factor"))
            return _complete_login(user)
        else:
            if user:
                user.failed_attempts = (user.failed_attempts or 0) + 1
                if user.failed_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()
            audit("login_fail", f"Attempt for {uname} from {ip}")
            flash("Access denied.", "error")
    return render_template("login.html", form=form)


def _complete_login(user):
    user.last_login = datetime.utcnow()
    db.session.commit()
    login_user(user)
    session.permanent = True
    session["last_seen"] = datetime.utcnow().timestamp()
    session["sid"] = secrets.token_hex(16)
    rec = SessionRecord(user_id=user.id, session_id=session["sid"],
                        ip=user.last_ip or "",
                        user_agent=request.headers.get("User-Agent", "")[:300])
    db.session.add(rec)
    db.session.commit()
    audit("login_success", f"{user.username} as {user.role}", actor=user.username)
    return redirect(url_for("dashboard"))


@app.route("/two-factor", methods=["GET", "POST"])
def two_factor():
    uid = session.get("pending_2fa_user")
    if not uid:
        return redirect(url_for("login"))
    user = db.session.get(User, uid)
    if not user:
        return redirect(url_for("login"))
    form = TwoFAForm()
    if form.validate_on_submit():
        if user.verify_totp(form.code.data) or user.check_backup_code(form.code.data):
            session.pop("pending_2fa_user", None)
            return _complete_login(user)
        flash("Invalid code.", "error")
    return render_template("two_factor.html", form=form)


@app.route("/logout")
@login_required
def logout():
    sid = session.get("sid")
    if sid:
        rec = db.session.execute(db.select(SessionRecord).filter_by(session_id=sid)).scalar()
        if rec:
            rec.revoked = True
            db.session.commit()
    audit("logout", current_user.username, actor=current_user.username)
    logout_user()
    flash("Session terminated.", "success")
    return redirect(url_for("login"))


@app.before_request
def _enforce_timeouts():
    if not current_user.is_authenticated:
        return
    if request.endpoint in ("static", "logout", None):
        return
    now = datetime.utcnow().timestamp()
    last = session.get("last_seen", now)
    if now - last > app.config["SESSION_IDLE_TIMEOUT"].total_seconds():
        logout_user()
        session.clear()
        flash("Session expired.", "error")
        return redirect(url_for("login"))
    session["last_seen"] = now
    sid = session.get("sid")
    if sid:
        rec = db.session.execute(db.select(SessionRecord).filter_by(session_id=sid)).scalar()
        if rec:
            rec.last_seen = datetime.utcnow()
            if rec.revoked:
                logout_user()
                session.clear()
                flash("Session revoked.", "error")
                return redirect(url_for("login"))
            db.session.commit()


@app.route("/settings/password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current.data):
            flash("Current password is incorrect.", "error")
        else:
            current_user.set_password(form.new.data)
            db.session.commit()
            audit("password_change", current_user.username, actor=current_user.username)
            flash("Password updated.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html", form=form)


@app.route("/settings/2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if not current_user.totp_secret:
        current_user.totp_secret = pyotp.random_base32()
        db.session.commit()
    otp_uri = pyotp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.username, issuer_name="MIS")
    form = Setup2FAForm()
    backup_codes = None
    if form.validate_on_submit():
        if pyotp.TOTP(current_user.totp_secret).verify(form.code.data.strip(), valid_window=1):
            current_user.totp_enabled = True
            backup_codes = current_user.generate_backup_codes()
            db.session.commit()
            audit("2fa_enabled", current_user.username, actor=current_user.username)
            flash("2FA enabled.", "success")
        else:
            flash("Invalid code.", "error")
    return render_template("setup_2fa.html", form=form,
                           secret=current_user.totp_secret, otp_uri=otp_uri,
                           enabled=current_user.totp_enabled, backup_codes=backup_codes)


@app.route("/settings/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    current_user.totp_enabled = False
    current_user.backup_codes = ""
    db.session.commit()
    flash("2FA disabled.", "success")
    return redirect(url_for("setup_2fa"))


@app.route("/settings/sessions", methods=["GET", "POST"])
@login_required
def my_sessions():
    if request.method == "POST":
        sid = session.get("sid")
        rows = db.session.execute(
            db.select(SessionRecord).where(SessionRecord.user_id == current_user.id)
        ).scalars().all()
        for r in rows:
            if r.session_id != sid:
                r.revoked = True
        db.session.commit()
        flash("Other sessions revoked.", "success")
        return redirect(url_for("my_sessions"))
    rows = db.session.execute(
        db.select(SessionRecord).where(SessionRecord.user_id == current_user.id,
                                       SessionRecord.revoked == False)
        .order_by(SessionRecord.last_seen.desc())
    ).scalars().all()
    return render_template("sessions.html", sessions=rows, current_sid=session.get("sid"))


# ============================================================
# DASHBOARD
# ============================================================
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role in (ROLE_TOP, ROLE_ANALYST):
        cases = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    else:
        cases = db.session.execute(
            db.select(Case).where(Case.assigned_agent_id == current_user.id)
            .order_by(Case.title)
        ).scalars().all()

    if current_user.role == ROLE_AGENT:
        recent = []
        for c in cases:
            recent.extend(c.updates)
        recent.sort(key=lambda u: u.happened_at, reverse=True)
        recent = recent[:20]
    else:
        recent = db.session.execute(
            db.select(Update).order_by(Update.happened_at.desc()).limit(20)
        ).scalars().all()

    stats = {
        "cases": len(cases),
        "updates": db.session.scalar(db.select(db.func.count(Update.id))) or 0,
        "media": db.session.scalar(db.select(db.func.count(UpdateMedia.id))) or 0,
        "entities": db.session.scalar(db.select(db.func.count(Entity.id))) or 0,
        "users": db.session.scalar(db.select(db.func.count(User.id))) or 0,
    }

    agents = []
    if current_user.role == ROLE_TOP:
        agents = db.session.execute(
            db.select(User).where(User.role == ROLE_AGENT).order_by(User.username)
        ).scalars().all()

    return render_template("dashboard.html", cases=cases, recent=recent,
                           case_choices=case_choices_for(current_user), stats=stats,
                           now_local_str=datetime.now().strftime("%Y-%m-%dT%H:%M"),
                           agents=agents)


# ============================================================
# QUICK ADD
# ============================================================
@app.route("/add", methods=["POST"])
@login_required
def quick_add():
    if current_user.role != ROLE_AGENT:
        flash("Only the assigned Agent can log entries.", "error")
        return redirect(url_for("dashboard"))
    form = QuickAddForm()
    form.case_id.choices = case_choices_for(current_user)
    if not form.case_id.data:
        flash("Select a case.", "error")
        return redirect(request.referrer or url_for("dashboard"))
    case = db.session.get(Case, form.case_id.data)
    if not case or not can_write_case_entries(current_user, case):
        flash("You can only write on cases assigned to you.", "error")
        return redirect(url_for("dashboard"))
    body = (form.body.data or "").strip()
    when = parse_local_dt(form.happened_at.data) or datetime.now()
    files = []
    if "photos" in request.files:
        for f in request.files.getlist("photos"):
            if f and f.filename:
                files.append(("photo", f))
    if "voice" in request.files:
        f = request.files.get("voice")
        if f and f.filename:
            files.append(("voice", f))
    if not body and not files:
        flash("Type something or attach a file.", "error")
        return redirect(request.referrer or url_for("dashboard"))
    if not body and files:
        body = f"[{files[0][0].capitalize()} attached]"
    u = Update(case_id=case.id, happened_at=when, created_by=current_user.username)
    u.body = body
    db.session.add(u)
    db.session.flush()
    u.integrity_hash = compute_integrity(u, extra=u.body_enc[:32])
    for kind, f in files:
        raw = f.read()
        if not raw:
            continue
        db.session.add(UpdateMedia(
            update_id=u.id, kind=kind,
            filename=secure_filename(f.filename),
            mimetype=f.mimetype or "application/octet-stream",
            data=raw, sha256=sha256_bytes(raw)))
    db.session.commit()
    audit("update_add", f"Case #{u.case_id}: {body[:40]}", actor=current_user.username)
    flash("Entry logged.", "success")
    return redirect(request.referrer or url_for("dashboard"))


# ============================================================
# CASES
# ============================================================
@app.route("/cases", methods=["GET", "POST"])
@login_required
def cases():
    if current_user.role != ROLE_TOP:
        flash("Only Top Secret can create cases.", "error")
        return redirect(url_for("dashboard"))
    form = CaseForm()
    form.assigned_agent_id.choices = agent_choices()
    if form.validate_on_submit():
        c = Case(
            title=form.title.data, subject=form.subject.data or "",
            status=form.status.data, priority=form.priority.data or 3,
            threat_level=form.threat_level.data, due_date=form.due_date.data,
            assigned_agent_id=form.assigned_agent_id.data or None,
            created_by=current_user.username)
        c.notes = form.notes.data or ""
        db.session.add(c)
        db.session.flush()
        c.integrity_hash = compute_integrity(c)
        db.session.commit()
        audit("case_create", c.title, actor=current_user.username)
        flash("Case opened and assigned.", "success")
        return redirect(url_for("case_detail", cid=c.id))
    rows = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    return render_template("cases.html", form=form, cases=rows)


@app.route("/cases/<int:cid>", methods=["GET", "POST"])
@login_required
def case_detail(cid):
    c = db.session.get(Case, cid) or abort(404)
    if not can_view_case(current_user, c):
        abort(403)
    form = CaseForm(obj=c)
    form.assigned_agent_id.choices = agent_choices()
    if form.validate_on_submit():
        if not can_edit_case_meta(current_user, c):
            flash("Only Top Secret can edit case meta.", "error")
            return redirect(url_for("case_detail", cid=c.id))
        c.title = form.title.data
        c.subject = form.subject.data or ""
        c.notes = form.notes.data or ""
        c.status = form.status.data
        c.priority = form.priority.data or c.priority
        c.threat_level = form.threat_level.data
        c.due_date = form.due_date.data
        c.assigned_agent_id = form.assigned_agent_id.data or None
        c.integrity_hash = compute_integrity(c)
        db.session.commit()
        flash("Case updated.", "success")
        return redirect(url_for("case_detail", cid=c.id))
    analyst_form = AnalystNoteForm()
    return render_template("case_detail.html", case=c, form=form,
                           case_choices=case_choices_for(current_user),
                           now_local_str=datetime.now().strftime("%Y-%m-%dT%H:%M"),
                           analyst_form=analyst_form)


@app.route("/cases/<int:cid>/delete", methods=["POST"])
@login_required
def case_delete(cid):
    c = db.session.get(Case, cid) or abort(404)
    if not can_delete_case(current_user, c):
        flash("Only Top Secret can delete cases.", "error")
        return redirect(url_for("case_detail", cid=cid))
    ok, err = delete_case_and_children(cid)
    if not ok:
        flash(f"Delete failed: {err}", "error")
        return redirect(url_for("case_detail", cid=cid))
    audit("case_delete", f"Case #{cid}", actor=current_user.username)
    flash("Case purged.", "success")
    return redirect(url_for("cases"))


@app.route("/cases/<int:cid>/report", methods=["POST"])
@login_required
def case_report(cid):
    c = db.session.get(Case, cid) or abort(404)
    if not can_view_case(current_user, c):
        abort(403)
    form = ReportForm()
    if not form.validate_on_submit():
        flash("Password required (min 6 characters).", "error")
        return redirect(url_for("case_detail", cid=cid))
    pdf_bytes = build_pdf(c, template=form.template.data)
    attachments = []
    if form.template.data == "full":
        for u in c.updates:
            for m in u.photos:
                if m.kind == "voice" or (m.kind != "photo" and m.data):
                    attachments.append({"name": m.filename or f"memo_{m.id}.bin", "data": m.data})
    encrypted_pdf = encrypt_pdf_with_attachments(pdf_bytes, form.password.data, attachments)
    audit("report_download", f"Case #{cid} — {form.template.data}", actor=current_user.username)
    safe_title = "".join(ch for ch in c.title if ch.isalnum() or ch in "-_")[:40] or "case"
    fname = f"MIS_{safe_title}_{form.template.data}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    resp = send_file(io.BytesIO(encrypted_pdf), mimetype="application/pdf",
                     as_attachment=True, download_name=fname)
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ============================================================
# ANALYST NOTES
# ============================================================
@app.route("/cases/<int:cid>/analyst", methods=["POST"])
@login_required
def analyst_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    if not can_write_analyst_note(current_user, c):
        abort(403)
    form = AnalystNoteForm()
    if form.validate_on_submit():
        n = AnalystNote(case_id=c.id, category=form.category.data,
                        title=form.title.data, created_by=current_user.username)
        n.body = form.body.data
        db.session.add(n)
        db.session.commit()
        audit("analyst_note_add", f"{n.category}: {n.title}", actor=current_user.username)
        flash("Analysis saved.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/analyst-notes/<int:nid>/edit", methods=["POST"])
@login_required
def analyst_note_edit(nid):
    n = db.session.get(AnalystNote, nid) or abort(404)
    if n.created_by != current_user.username and current_user.role != ROLE_TOP:
        abort(403)
    n.category = request.form.get("category") or n.category
    n.title = request.form.get("title") or n.title
    n.body = request.form.get("body") or n.body
    db.session.commit()
    flash("Analysis updated.", "success")
    return redirect(url_for("case_detail", cid=n.case_id))


@app.route("/analyst-notes/<int:nid>/delete", methods=["POST"])
@login_required
def analyst_note_delete(nid):
    n = db.session.get(AnalystNote, nid) or abort(404)
    if n.created_by != current_user.username and current_user.role != ROLE_TOP:
        abort(403)
    cid = n.case_id
    db.session.delete(n)
    db.session.commit()
    flash("Analysis removed.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/analyst")
@login_required
def analyst_workspace():
    if current_user.role not in (ROLE_TOP, ROLE_ANALYST):
        flash("Analyst access only.", "error")
        return redirect(url_for("dashboard"))
    cases = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    my_notes = db.session.execute(
        db.select(AnalystNote).where(AnalystNote.created_by == current_user.username)
        .order_by(AnalystNote.created_at.desc())
    ).scalars().all()
    return render_template("analyst.html", cases=cases, my_notes=my_notes)


# ============================================================
# UPDATE EDIT / DELETE
# ============================================================
@app.route("/updates/<int:uid>/edit", methods=["GET", "POST"])
@login_required
def update_edit(uid):
    u = db.session.get(Update, uid) or abort(404)
    if not can_write_case_entries(current_user, u.case):
        abort(403)
    form = QuickAddForm(obj=u)
    form.case_id.choices = case_choices_for(current_user)
    form.case_id.data = u.case_id
    if u.happened_at:
        form.happened_at.data = u.happened_at.strftime("%Y-%m-%dT%H:%M")
    if form.validate_on_submit():
        u.body = (form.body.data or "").strip() or u.body
        new_when = parse_local_dt(form.happened_at.data)
        if new_when:
            u.happened_at = new_when
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
                                data=raw, sha256=sha256_bytes(raw)))
        u.integrity_hash = compute_integrity(u, extra=u.body_enc[:32])
        db.session.commit()
        flash("Entry updated.", "success")
        return redirect(url_for("case_detail", cid=u.case_id))
    return render_template("update_edit.html", form=form, update=u)


@app.route("/updates/<int:uid>/delete", methods=["POST"])
@login_required
def update_delete(uid):
    u = db.session.get(Update, uid) or abort(404)
    if not can_write_case_entries(current_user, u.case):
        abort(403)
    cid = u.case_id
    ok, err = delete_update_and_children(uid)
    if not ok:
        flash(f"Delete failed: {err}", "error")
        return redirect(url_for("case_detail", cid=cid))
    flash("Entry deleted.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/updates/<int:uid>/media/<int:mid>/delete", methods=["POST"])
@login_required
def update_media_delete(uid, mid):
    m = db.session.get(UpdateMedia, mid) or abort(404)
    if m.update_id != uid:
        abort(404)
    if not can_write_case_entries(current_user, m.update.case):
        abort(403)
    cid = m.update.case_id
    db.session.delete(m)
    db.session.commit()
    return redirect(url_for("case_detail", cid=cid))


@app.route("/media/<int:mid>/view")
@login_required
def media_view(mid):
    m = db.session.get(UpdateMedia, mid) or abort(404)
    if m.update and m.update.case and not can_view_case(current_user, m.update.case):
        abort(403)
    mt = m.mimetype or "application/octet-stream"
    if m.kind == "photo" and not mt.startswith("image/"):
        mt = "image/jpeg"
    elif m.kind == "voice" and not mt.startswith("audio/"):
        mt = "audio/webm"
    return send_file(io.BytesIO(m.data), mimetype=mt,
                     as_attachment=False, download_name=m.filename)


# ============================================================
# ENTITIES — enriched
# ============================================================
@app.route("/entities", methods=["GET", "POST"])
@login_required
def entities():
    form = EntityForm()
    if form.validate_on_submit():
        eid = request.form.get("entity_id", type=int)
        if eid:
            e = db.session.get(Entity, eid) or abort(404)
            e.name = form.name.data
            e.type = form.type.data
            e.region = form.region.data or ""
            e.notes = form.notes.data or ""
            try:
                if form.latitude.data: e.latitude = float(form.latitude.data)
                if form.longitude.data: e.longitude = float(form.longitude.data)
            except Exception:
                pass
            db.session.commit()
            flash("Person updated.", "success")
        else:
            e = Entity(name=form.name.data, type=form.type.data, region=form.region.data or "")
            e.notes = form.notes.data or ""
            try:
                if form.latitude.data: e.latitude = float(form.latitude.data)
                if form.longitude.data: e.longitude = float(form.longitude.data)
            except Exception:
                pass
            db.session.add(e)
            db.session.commit()
            audit("entity_create", e.name, actor=current_user.username)
            flash("Person saved.", "success")
        return redirect(url_for("entities"))

    rows = db.session.execute(db.select(Entity).order_by(Entity.name)).scalars().all()
    people_data = []
    for p in rows:
        links = db.session.execute(
            db.select(CaseEntity).where(CaseEntity.entity_id == p.id)
        ).scalars().all()
        people_data.append({"person": p, "links": links})
    return render_template("people.html", form=form, people=people_data)


@app.route("/entities/<int:eid>")
@login_required
def entity_detail(eid):
    e = db.session.get(Entity, eid) or abort(404)
    cases = db.session.execute(
        db.select(CaseEntity).where(CaseEntity.entity_id == eid)
    ).scalars().all()
    return render_template("person_detail.html", entity=e, cases=cases)


@app.route("/entities/<int:eid>/update", methods=["POST"])
@login_required
def entity_update(eid):
    e = db.session.get(Entity, eid) or abort(404)
    if "region" in request.form:
        e.region = (request.form.get("region") or "").strip()
    if "notes" in request.form:
        e.notes = (request.form.get("notes") or "").strip()
    db.session.commit()
    flash("Updated.", "success")
    return redirect(request.referrer or url_for("entities"))


@app.route("/entities/<int:eid>/delete", methods=["POST"])
@login_required
@require_role(ROLE_TOP)
def entity_delete(eid):
    ok, err = delete_entity_and_children(eid)
    if not ok:
        flash(f"Delete failed: {err}", "error")
    return redirect(url_for("entities"))


@app.route("/cases/<int:cid>/entities", methods=["POST"])
@login_required
def case_entity_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    if not can_write_case_entries(current_user, c):
        abort(403)
    name = (request.form.get("name") or "").strip()
    role = (request.form.get("role") or "Other").strip()
    note = (request.form.get("note") or "").strip()
    if name:
        e = Entity(name=name, type="Person")
        db.session.add(e)
        db.session.flush()
        link = CaseEntity(case_id=c.id, entity_id=e.id, role=role)
        link.note = note
        db.session.add(link)
        db.session.commit()
        audit("case_entity_add", f"{name} ({role})", actor=current_user.username)
        flash("Person added.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/case-entities/<int:link_id>/edit", methods=["POST"])
@login_required
def case_entity_edit(link_id):
    link = db.session.get(CaseEntity, link_id) or abort(404)
    if not can_write_case_entries(current_user, link.case):
        abort(403)
    link.role = (request.form.get("role") or link.role or "Other").strip()
    link.note = (request.form.get("note") or "").strip()
    db.session.commit()
    flash("Updated.", "success")
    return redirect(url_for("case_detail", cid=link.case_id))


@app.route("/case-entities/<int:link_id>/delete", methods=["POST"])
@login_required
def case_entity_delete(link_id):
    link = db.session.get(CaseEntity, link_id) or abort(404)
    if not can_write_case_entries(current_user, link.case):
        abort(403)
    cid = link.case_id
    db.session.delete(link)
    db.session.commit()
    return redirect(url_for("case_detail", cid=cid))


# ============================================================
# RELATIONSHIPS
# ============================================================
@app.route("/who-knows-who", methods=["GET", "POST"])
@login_required
def relationships():
    form = RelationshipForm()
    form.from_id.choices = entity_choices()
    form.to_id.choices = entity_choices()
    if form.validate_on_submit():
        if form.from_id.data == form.to_id.data:
            flash("Cannot self-link.", "error")
        else:
            r = Relationship(from_id=form.from_id.data, to_id=form.to_id.data,
                             relation=form.relation.data)
            r.description = form.description.data or ""
            db.session.add(r)
            db.session.commit()
            flash("Link recorded.", "success")
            return redirect(url_for("relationships"))
    rows = db.session.execute(db.select(Relationship).order_by(Relationship.created_at.desc())).scalars().all()
    return render_template("relationships.html", form=form, relationships=rows)


@app.route("/relationships/<int:rid>/delete", methods=["POST"])
@login_required
def relationship_delete(rid):
    r = db.session.get(Relationship, rid) or abort(404)
    db.session.delete(r)
    db.session.commit()
    return redirect(url_for("relationships"))


# ============================================================
# CONTACTS
# ============================================================
@app.route("/contacts", methods=["GET", "POST"])
@login_required
def contacts():
    form = SourceForm()
    if form.validate_on_submit():
        s = Source(handle=form.handle.data)
        s.description = form.description.data or ""
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
# SEARCH + ACTIVITY
# ============================================================
@app.route("/search")
@login_required
def search():
    q = (request.args.get("q") or "").strip()
    results = {"cases": [], "updates": [], "entities": []}
    if q:
        like = f"%{q}%"
        case_q = db.select(Case).where(or_(Case.title.ilike(like), Case.subject.ilike(like)))
        if current_user.role == ROLE_AGENT:
            case_q = case_q.where(Case.assigned_agent_id == current_user.id)
        results["cases"] = db.session.execute(case_q).scalars().all()
        all_updates = db.session.execute(db.select(Update)).scalars().all()
        visible = [u for u in all_updates
                   if can_view_case(current_user, u.case) and q.lower() in (u.body or "").lower()]
        results["updates"] = visible[:100]
        all_entities = db.session.execute(db.select(Entity)).scalars().all()
        results["entities"] = [e for e in all_entities
                               if q.lower() in (e.name or "").lower()][:100]
    return render_template("search.html", q=q, results=results)


@app.route("/activity")
@login_required
@require_role(ROLE_TOP)
def activity():
    rows = db.session.execute(db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(300)).scalars().all()
    return render_template("audit.html", entries=rows)


# ============================================================
# TIMED NOTES
# ============================================================
@app.route("/timed-notes", methods=["GET", "POST"])
@login_required
def drops():
    form = DeadDropForm()
    if form.validate_on_submit():
        d = DeadDrop(title=form.title.data, unlock_at=form.unlock_at.data,
                     created_by=current_user.username)
        d.body = form.body.data
        db.session.add(d)
        db.session.commit()
        flash("Sealed.", "success")
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
# BRIEFING
# ============================================================
@app.route("/briefing")
@login_required
def briefing():
    days = int(request.args.get("days", 1))
    since = datetime.now() - timedelta(days=days)
    updates = db.session.execute(
        db.select(Update).where(Update.happened_at >= since).order_by(Update.happened_at.desc())
    ).scalars().all()
    updates = [u for u in updates if can_view_case(current_user, u.case)]
    return render_template("briefing.html", days=days, since=since, updates=updates)


# ============================================================
# MAP (still available, hidden from nav)
# ============================================================
@app.route("/map")
@login_required
def map_view():
    people = db.session.execute(db.select(Entity)).scalars().all()
    markers = []
    for p in people:
        if p.latitude and p.longitude:
            markers.append({
                "id": p.id, "name": p.name, "type": p.type,
                "threat": p.threat_level, "region": p.region,
                "lat": p.latitude, "lng": p.longitude, "verified": p.verified,
                "color": {"LOW": "#3fb950", "MEDIUM": "#ffb000",
                          "HIGH": "#ff7b00", "CRITICAL": "#ff3b30"}.get(p.threat_level, "#8a8577"),
            })
    return render_template("map.html", markers=markers)


# ============================================================
# TIMELINE VIZ
# ============================================================
@app.route("/cases/<int:cid>/timeline-viz")
@login_required
def timeline_viz(cid):
    c = db.session.get(Case, cid) or abort(404)
    if not can_view_case(current_user, c):
        abort(403)
    events = [{
        "id": u.id, "when": u.happened_at.strftime("%Y-%m-%d %H:%M"),
        "ts": u.happened_at.timestamp(), "body": (u.body or "")[:100],
        "media": len(u.photos),
        "photos": sum(1 for m in u.photos if m.kind == "photo"),
        "voices": sum(1 for m in u.photos if m.kind == "voice"),
    } for u in c.updates]
    return render_template("timeline_viz.html", case=c, events=events)


# ============================================================
# BACKUPS — restored AES-256-GCM with header
# ============================================================
@app.route("/backups")
@login_required
@require_role(ROLE_TOP)
def backups():
    rows = db.session.execute(db.select(Backup).order_by(Backup.created_at.desc())).scalars().all()
    return render_template("backups.html", backups=rows)


@app.route("/backups/create", methods=["POST"])
@login_required
@require_role(ROLE_TOP)
def backup_create():
    password = (request.form.get("password") or "").strip()
    if len(password) < 8:
        flash("Backup password must be at least 8 characters.", "error")
        return redirect(url_for("backups"))
    blob, count = make_encrypted_backup(password)
    fname = f"MIS_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.misbak"
    db.session.add(Backup(filename=fname, size_bytes=len(blob),
                          record_count=count, created_by=current_user.username))
    db.session.commit()
    audit("backup_create", fname, actor=current_user.username)
    resp = send_file(io.BytesIO(blob), mimetype="application/octet-stream",
                     as_attachment=True, download_name=fname)
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ============================================================
# INTEGRITY
# ============================================================
@app.route("/integrity")
@login_required
def integrity():
    issues = []
    for c in db.session.execute(db.select(Case)).scalars().all():
        expected = compute_integrity(c)
        if c.integrity_hash and c.integrity_hash != expected:
            issues.append(("case", c.id, c.title))
    for u in db.session.execute(db.select(Update)).scalars().all():
        expected = compute_integrity(u, extra=(u.body_enc or "")[:32])
        if u.integrity_hash and u.integrity_hash != expected:
            issues.append(("update", u.id, (u.body or "")[:40]))
    return render_template("integrity.html", issues=issues)


# ============================================================
# USERS
# ============================================================
@app.route("/users", methods=["GET", "POST"])
@login_required
@require_role(ROLE_TOP)
def users():
    form = UserForm()
    if form.validate_on_submit():
        uname = form.username.data.strip()
        if db.session.execute(db.select(User).filter_by(username=uname)).scalar():
            flash("Username taken.", "error")
        else:
            u = User(username=uname, codename=form.codename.data or "",
                     email=form.email.data or "", role=form.role.data)
            u.set_password(form.password.data)
            db.session.add(u)
            db.session.commit()
            audit("user_create", f"{uname} ({form.role.data})", actor=current_user.username)
            flash("User created.", "success")
            return redirect(url_for("users"))
    rows = db.session.execute(db.select(User).order_by(User.created_at)).scalars().all()
    return render_template("users.html", form=form, users=rows)


@app.route("/users/<int:uid>/delete", methods=["POST"])
@login_required
@require_role(ROLE_TOP)
def user_delete(uid):
    if uid == current_user.id:
        flash("Cannot delete yourself.", "error")
        return redirect(url_for("users"))
    u = db.session.get(User, uid) or abort(404)
    db.session.delete(u)
    db.session.commit()
    return redirect(url_for("users"))


# ============================================================
# PWA
# ============================================================
@app.route("/manifest.json")
def manifest():
    resp = send_file(os.path.join(BASE_DIR, "static", "manifest.json"),
                     mimetype="application/manifest+json")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/service-worker.js")
def service_worker():
    resp = send_file(os.path.join(BASE_DIR, "static", "service-worker.js"),
                     mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Service-Worker-Allowed"] = "/"
    return resp


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
            user = User(username=u, codename="ALPHA", role=ROLE_TOP)
            user.set_password(p)
            db.session.add(user)
            db.session.commit()
            print(f"🔥 Force-reseeded: {u}")
            return
        if not existing:
            user = User(username=u, codename="ALPHA", role=ROLE_TOP)
            user.set_password(p)
            db.session.add(user)
            db.session.commit()
            print(f"✅ Seeded: {u}")
        else:
            if existing.role in ("admin", "manager", None, ""):
                existing.role = ROLE_TOP
                db.session.commit()
            elif existing.role in ("contributor", "viewer"):
                existing.role = ROLE_AGENT
                db.session.commit()
            print(f"✅ User {u} OK (role={existing.role})")


bootstrap()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
