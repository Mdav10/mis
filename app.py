# ============================================================
# MIS v12 — Complete Professional Build
# 1. Two-Factor Auth     2. DB Encryption at Rest
# 3. Session Hardening   4. Integrity Monitoring
# 5. Encrypted Backups   6. Timeline Visualization
# 7. Contradiction       8. Report Templates
# 9. RBAC               10. Map View
# ============================================================

import os, io, json, hmac, hashlib, secrets, base64, re, csv
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
from flask_wtf.file import FileField, FileRequired
from wtforms import (
    StringField, PasswordField, TextAreaField, SelectField,
    BooleanField, SubmitField, DateTimeField, IntegerField, HiddenField
)
from wtforms.validators import DataRequired, Length, EqualTo, Optional, Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy import or_, and_, text, inspect

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
)
from reportlab.lib import colors

from pypdf import PdfReader, PdfWriter

import pyotp
import qrcode
import io as _io

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
# CRYPTO HELPERS
# ============================================================
MASTER_KEY_ENV = os.getenv("MASTER_KEY", "")  # 64-hex chars, set in Render env


def get_master_key():
    """Returns 32-byte master key derived from env MASTER_KEY."""
    raw = MASTER_KEY_ENV.strip()
    if not raw:
        # fallback: derive from SECRET_KEY (not ideal, but keeps app bootable)
        raw = hashlib.sha256(app.config["SECRET_KEY"].encode()).hexdigest()
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    return hashlib.sha256(raw.encode()).digest()


def field_encrypt(plaintext: str) -> str:
    """Encrypt a text field for storage. Returns base64(MIS1|salt|nonce|ct)."""
    if plaintext is None:
        return ""
    if plaintext == "":
        return ""
    try:
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = get_master_key()
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"),
                                  associated_data=b"MIS_FIELD")
        return base64.b64encode(b"MIS1" + salt + nonce + ct).decode("ascii")
    except Exception:
        return plaintext  # fallback: store as-is if crypto fails


def field_decrypt(stored: str) -> str:
    """Decrypt a text field. Falls back to plaintext if not encrypted."""
    if not stored:
        return ""
    try:
        blob = base64.b64decode(stored, validate=True)
        if blob[:4] != b"MIS1":
            return stored
        salt, nonce, ct = blob[4:20], blob[20:32], blob[32:]
        # salt unused because master key is fixed, but kept for format compat
        key = get_master_key()
        pt = AESGCM(key).decrypt(nonce, ct, associated_data=b"MIS_FIELD")
        return pt.decode("utf-8")
    except Exception:
        return stored


# ============================================================
# TIME HELPERS
# ============================================================
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
# MODELS
# ============================================================
class User(UserMixin, db.Model):
    __tablename__ = "mis_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    codename = db.Column(db.String(80), default="")
    email = db.Column(db.String(160), default="")
    role = db.Column(db.String(20), default="admin")  # admin/manager/analyst/contributor/viewer
    clearance = db.Column(db.String(40), default="SECRET")
    totp_secret = db.Column(db.String(80), default="")   # base32
    totp_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text, default="")        # newline-separated hashed codes
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
            totp = pyotp.TOTP(self.totp_secret)
            return totp.verify(str(code).strip(), valid_window=1)
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
        self.backup_codes = "\n".join(hashlib.sha256(c.replace("-","").upper().encode()).hexdigest() for c in codes)
        return codes


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
    notes_enc = db.Column(db.Text, default="")   # encrypted
    status = db.Column(db.String(40), default="Active")
    classification = db.Column(db.String(40), default="SECRET")
    threat_level = db.Column(db.String(20), default="MEDIUM")
    priority = db.Column(db.Integer, default=3)
    due_date = db.Column(db.DateTime, nullable=True)
    integrity_hash = db.Column(db.String(64), default="")
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    updates = db.relationship("Update", backref="case", lazy=True,
                              cascade="all, delete-orphan",
                              order_by="Update.happened_at.desc()")
    links = db.relationship("CaseEntity", backref="case", lazy=True,
                            cascade="all, delete-orphan")
    access = db.relationship("CaseAccess", backref="case", lazy=True,
                             cascade="all, delete-orphan")

    @property
    def notes(self):
        return field_decrypt(self.notes_enc or "")

    @notes.setter
    def notes(self, value):
        self.notes_enc = field_encrypt(value or "")


class CaseAccess(db.Model):
    __tablename__ = "mis_case_access"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    can_write = db.Column(db.Boolean, default=True)
    can_delete = db.Column(db.Boolean, default=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)


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
    def body(self):
        return field_decrypt(self.body_enc or "")

    @body.setter
    def body(self, value):
        self.body_enc = field_encrypt(value or "")


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
    def notes(self):
        return field_decrypt(self.notes_enc or "")

    @notes.setter
    def notes(self, value):
        self.notes_enc = field_encrypt(value or "")


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
    def note(self):
        return field_decrypt(self.note_enc or "")

    @note.setter
    def note(self, value):
        self.note_enc = field_encrypt(value or "")


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
    def description(self):
        return field_decrypt(self.description_enc or "")

    @description.setter
    def description(self, value):
        self.description_enc = field_encrypt(value or "")


class Source(db.Model):
    __tablename__ = "mis_sources"
    id = db.Column(db.Integer, primary_key=True)
    handle = db.Column(db.String(120), nullable=False)
    description_enc = db.Column(db.Text, default="")
    case_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def description(self):
        return field_decrypt(self.description_enc or "")

    @description.setter
    def description(self, value):
        self.description_enc = field_encrypt(value or "")


class DeadDrop(db.Model):
    __tablename__ = "mis_dead_drops"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body_enc = db.Column(db.Text, default="")
    unlock_at = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(80), default="system")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def body(self):
        return field_decrypt(self.body_enc or "")

    @body.setter
    def body(self, value):
        self.body_enc = field_encrypt(value or "")

    @property
    def is_unlocked(self):
        return datetime.now() >= self.unlock_at

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
        ("role", "VARCHAR(20) DEFAULT 'admin'"),
        ("clearance", "VARCHAR(40) DEFAULT 'SECRET'"),
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
        ("classification", "VARCHAR(40) DEFAULT 'SECRET'"),
        ("priority", "INTEGER DEFAULT 3"),
        ("due_date", "TIMESTAMP"),
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
    "mis_relationships": [
        ("description_enc", "TEXT DEFAULT ''"),
        ("case_id", "INTEGER"),
    ],
    "mis_sources": [
        ("description_enc", "TEXT DEFAULT ''"),
        ("case_id", "INTEGER"),
    ],
    "mis_dead_drops": [
        ("body_enc", "TEXT DEFAULT ''"),
        ("created_by", "VARCHAR(80) DEFAULT 'system'"),
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
# INTEGRITY
# ============================================================
def compute_integrity(obj, extra=""):
    parts = []
    for col in ("id", "created_at"):
        v = getattr(obj, col, None)
        parts.append(str(v) if v is not None else "")
    for col in ("title", "subject", "status", "threat_level", "priority"):
        if hasattr(obj, col):
            v = getattr(obj, col)
            parts.append(str(v) if v is not None else "")
    parts.append(extra)
    payload = "|".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ============================================================
# RBAC DECORATOR
# ============================================================
def require_role(*roles):
    def wrapper(fn):
        @wraps(fn)
        def inner(*a, **kw):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles and current_user.role != "admin":
                flash("Insufficient clearance.", "error")
                return redirect(url_for("dashboard"))
            return fn(*a, **kw)
        return inner
    return wrapper


def require_password(fn):
    """Requires the current user to have re-entered their password within 5 min."""
    @wraps(fn)
    def inner(*a, **kw):
        ts = session.get("reauth_until")
        if not ts or datetime.utcnow().timestamp() > ts:
            flash("Please re-enter your password to continue.", "error")
            return redirect(url_for("reauth", next=request.path))
        return fn(*a, **kw)
    return inner


# ============================================================
# BULLETPROOF DELETES
# ============================================================
def delete_case_and_children(cid):
    try:
        with db.engine.begin() as conn:
            conn.execute(text("""
                DELETE FROM mis_update_media
                WHERE update_id IN (SELECT id FROM mis_updates WHERE case_id = :cid)
            """), {"cid": cid})
            for tbl, col in [
                ("mis_case_access", "case_id"),
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


class ReauthForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Confirm")


class ChangePasswordForm(FlaskForm):
    current = PasswordField("Current Password", validators=[DataRequired()])
    new = PasswordField("New Password", validators=[DataRequired(), Length(min=10)])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("new")])
    submit = SubmitField("Update Password")


class Setup2FAForm(FlaskForm):
    code = StringField("Enter 6-digit code from your app", validators=[DataRequired(), Length(6)])
    submit = SubmitField("Enable 2FA")


class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    codename = StringField("Display name", validators=[Optional(), Length(0, 80)])
    email = StringField("Email", validators=[Optional(), Email(), Length(0, 160)])
    role = SelectField("Role", choices=[
        ("admin", "Admin"), ("manager", "Manager"),
        ("analyst", "Analyst"), ("contributor", "Contributor"),
        ("viewer", "Viewer"),
    ], default="analyst")
    clearance = SelectField("Clearance", choices=[
        ("CONFIDENTIAL", "Confidential"), ("SECRET", "Secret"),
        ("TOP_SECRET", "Top Secret"), ("EYES_ONLY", "Eyes Only"),
    ], default="SECRET")
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
        (1, "1 — Critical"), (2, "2 — High"),
        (3, "3 — Standard"), (4, "4 — Low")
    ])
    threat_level = SelectField("Threat", choices=[
        ("LOW", "Low"), ("MEDIUM", "Medium"), ("HIGH", "High"), ("CRITICAL", "Critical")
    ], default="MEDIUM")
    due_date = DateTimeField("Reminder — YYYY-MM-DD HH:MM",
                             format="%Y-%m-%d %H:%M", validators=[Optional()])
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


class AccessForm(FlaskForm):
    user_id = SelectField("User", coerce=int, validators=[DataRequired()])
    can_write = BooleanField("Can write", default=True)
    can_delete = BooleanField("Can delete", default=False)
    submit = SubmitField("Grant Access")


# ============================================================
# HELPERS
# ============================================================
def case_choices():
    rows = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    return [(c.id, c.title) for c in rows]


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


def can_view_case(user, case):
    if user.role in ("admin", "manager"):
        return True
    links = db.session.execute(
        db.select(CaseAccess).where(CaseAccess.case_id == case.id,
                                    CaseAccess.user_id == user.id)
    ).scalars().all()
    if links:
        return True
    return case.created_by == user.username


def can_write_case(user, case):
    if user.role in ("admin", "manager"):
        return True
    link = db.session.execute(
        db.select(CaseAccess).where(CaseAccess.case_id == case.id,
                                    CaseAccess.user_id == user.id)
    ).scalar()
    if link and link.can_write:
        return True
    return case.created_by == user.username


def can_delete_case(user, case):
    if user.role == "admin":
        return True
    link = db.session.execute(
        db.select(CaseAccess).where(CaseAccess.case_id == case.id,
                                    CaseAccess.user_id == user.id)
    ).scalar()
    if link and link.can_delete:
        return True
    return False


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
    story.append(Paragraph(f"Status: {esc(case.status)} · Threat: {esc(case.threat_level)} · Priority: {case.priority}", body))
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
        all_media = []
        for u in case.updates:
            for m in u.photos:
                all_media.append((u.happened_at, u.id, m))
        if all_media:
            data = [["When", "Entry", "Kind", "File", "SHA-256"]]
            for when, uid, m in all_media:
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

    if template in ("full", "gaps"):
        story.append(PageBreak())
        story.append(Paragraph("Gap Analysis", h2))
        story.append(Paragraph(f"Total entries: {len(case.updates)}", body))
        story.append(Paragraph(f"Total people: {len(case.links)}", body))
        if case.updates:
            srt = sorted(case.updates, key=lambda u: u.happened_at)
            gaps = []
            for i in range(1, len(srt)):
                delta = srt[i].happened_at - srt[i-1].happened_at
                if delta.days >= 14:
                    gaps.append((srt[i-1].happened_at, srt[i].happened_at, delta.days))
            if gaps:
                story.append(Paragraph("Periods with 14+ day gaps:", h3))
                for a, b, d in gaps:
                    story.append(Paragraph(f"· {a.strftime('%d %b %Y')} → {b.strftime('%d %b %Y')} ({d} days)", body))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Unverified / Disputed", h3))
        story.append(Paragraph("Review all entries flagged in the Timeline.", body))

    doc.build(story)
    return buf.getvalue()


def encrypt_pdf_with_attachments(pdf_bytes, password, attachments):
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    for att in attachments:
        try:
            writer.add_attachment(filename=att["name"], data=att["data"])
        except Exception as e:
            print(f"⚠️  Could not attach {att.get('name')}: {e}")
    writer.encrypt(user_password=password, owner_password=password,
                   permissions_flag=-1, algorithm="AES-256")
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


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
            flash(f"Account locked. Try again after {user.locked_until.strftime('%H:%M')}.", "error")
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
                        ip=user.last_ip or "", user_agent=request.headers.get("User-Agent", "")[:300])
    db.session.add(rec)
    db.session.commit()
    audit("login_success", f"{user.username} logged in", actor=user.username)
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
        code = form.code.data.strip()
        if user.verify_totp(code) or user.check_backup_code(code):
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
        flash("Session expired. Please log in.", "error")
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


@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    form = ReauthForm()
    if form.validate_on_submit():
        if current_user.check_password(form.password.data):
            session["reauth_until"] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()
            nxt = request.args.get("next") or url_for("dashboard")
            return redirect(nxt)
        flash("Incorrect password.", "error")
    return render_template("reauth.html", form=form)


# ============================================================
# 2FA SETUP
# ============================================================
@app.route("/settings/2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if not current_user.totp_secret:
        current_user.totp_secret = pyotp.random_base32()
        db.session.commit()

    otp_uri = pyotp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.username, issuer_name="MIS"
    )
    qr = qrcode.make(otp_uri)
    qr_buf = _io.BytesIO()
    qr.save(qr_buf, format="PNG")
    qr_b64 = base64.b64encode(qr_buf.getvalue()).decode()

    form = Setup2FAForm()
    backup_codes = None
    if form.validate_on_submit():
        if pyotp.TOTP(current_user.totp_secret).verify(form.code.data.strip(), valid_window=1):
            current_user.totp_enabled = True
            backup_codes = current_user.generate_backup_codes()
            db.session.commit()
            audit("2fa_enabled", current_user.username, actor=current_user.username)
            flash("2FA enabled. Save your backup codes now.", "success")
        else:
            flash("Invalid code. Try again.", "error")

    return render_template("setup_2fa.html", form=form, qr_b64=qr_b64,
                           secret=current_user.totp_secret,
                           enabled=current_user.totp_enabled,
                           backup_codes=backup_codes)


@app.route("/settings/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    current_user.totp_enabled = False
    current_user.backup_codes = ""
    db.session.commit()
    audit("2fa_disabled", current_user.username, actor=current_user.username)
    flash("2FA disabled.", "success")
    return redirect(url_for("setup_2fa"))


@app.route("/settings/sessions", methods=["GET", "POST"])
@login_required
def my_sessions():
    if request.method == "POST":
        # Revoke all other sessions
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
    current_sid = session.get("sid")
    return render_template("sessions.html", sessions=rows, current_sid=current_sid)


# ============================================================
# ROUTES — DASHBOARD
# ============================================================
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role in ("admin", "manager"):
        cases = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    else:
        accessible = db.session.execute(
            db.select(CaseAccess.case_id).where(CaseAccess.user_id == current_user.id)
        ).scalars().all()
        cases = db.session.execute(
            db.select(Case).where(
                or_(Case.id.in_(accessible), Case.created_by == current_user.username)
            ).order_by(Case.title)
        ).scalars().all()

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

    # integrity issues (if hash mismatch)
    integrity_issues = []
    for c in cases[:50]:
        expected = compute_integrity(c)
        if c.integrity_hash and c.integrity_hash != expected:
            integrity_issues.append(c)

    return render_template("dashboard.html", cases=cases, recent=recent,
                           case_choices=case_choices(), stats=stats,
                           now_local_str=datetime.now().strftime("%Y-%m-%dT%H:%M"),
                           integrity_issues=integrity_issues)


# ============================================================
# ROUTES — QUICK ADD
# ============================================================
@app.route("/add", methods=["POST"])
@login_required
def quick_add():
    form = QuickAddForm()
    form.case_id.choices = case_choices()
    if not form.case_id.data:
        flash("Select a case.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    case = db.session.get(Case, form.case_id.data)
    if not case or not can_write_case(current_user, case):
        flash("You don't have write access to that case.", "error")
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
            data=raw, sha256=sha256_bytes(raw),
        ))

    db.session.commit()
    audit("update_add", f"Case #{u.case_id}: {body[:40]}", actor=current_user.username)
    flash("Entry logged.", "success")
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
            status=form.status.data,
            priority=form.priority.data or 3,
            threat_level=form.threat_level.data,
            due_date=form.due_date.data,
            created_by=current_user.username,
        )
        c.notes = form.notes.data or ""
        db.session.add(c)
        db.session.flush()
        c.integrity_hash = compute_integrity(c)
        db.session.commit()
        audit("case_create", c.title, actor=current_user.username)
        flash("Case opened.", "success")
        return redirect(url_for("case_detail", cid=c.id))

    if current_user.role in ("admin", "manager"):
        rows = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    else:
        accessible = db.session.execute(
            db.select(CaseAccess.case_id).where(CaseAccess.user_id == current_user.id)
        ).scalars().all()
        rows = db.session.execute(
            db.select(Case).where(
                or_(Case.id.in_(accessible), Case.created_by == current_user.username)
            ).order_by(Case.title)
        ).scalars().all()
    return render_template("cases.html", form=form, cases=rows)


@app.route("/cases/<int:cid>", methods=["GET", "POST"])
@login_required
def case_detail(cid):
    c = db.session.get(Case, cid) or abort(404)
    if not can_view_case(current_user, c):
        abort(403)

    form = CaseForm(obj=c)
    if form.validate_on_submit():
        if not can_write_case(current_user, c):
            flash("Read-only access.", "error")
            return redirect(url_for("case_detail", cid=c.id))
        c.title = form.title.data
        c.subject = form.subject.data or ""
        c.notes = form.notes.data or ""
        c.status = form.status.data
        c.priority = form.priority.data or c.priority
        c.threat_level = form.threat_level.data
        c.due_date = form.due_date.data
        c.integrity_hash = compute_integrity(c)
        db.session.commit()
        flash("Case updated.", "success")
        return redirect(url_for("case_detail", cid=c.id))

    access_form = AccessForm()
    access_form.user_id.choices = user_choices()

    return render_template(
        "case_detail.html", case=c, form=form,
        case_choices=case_choices(), access_form=access_form,
        now_local_str=datetime.now().strftime("%Y-%m-%dT%H:%M"),
        users=db.session.execute(db.select(User)).scalars().all(),
    )


@app.route("/cases/<int:cid>/access/add", methods=["POST"])
@login_required
@require_role("admin", "manager")
def case_access_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    form = AccessForm()
    form.user_id.choices = user_choices()
    if form.validate_on_submit():
        existing = db.session.execute(
            db.select(CaseAccess).where(CaseAccess.case_id == c.id,
                                        CaseAccess.user_id == form.user_id.data)
        ).scalar()
        if existing:
            existing.can_write = form.can_write.data
            existing.can_delete = form.can_delete.data
        else:
            db.session.add(CaseAccess(
                case_id=c.id, user_id=form.user_id.data,
                can_write=form.can_write.data, can_delete=form.can_delete.data
            ))
        db.session.commit()
        flash("Access updated.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/cases/<int:cid>/access/<int:aid>/remove", methods=["POST"])
@login_required
@require_role("admin", "manager")
def case_access_remove(cid, aid):
    link = db.session.get(CaseAccess, aid) or abort(404)
    db.session.delete(link)
    db.session.commit()
    return redirect(url_for("case_detail", cid=cid))


@app.route("/cases/<int:cid>/delete", methods=["POST"])
@login_required
def case_delete(cid):
    c = db.session.get(Case, cid) or abort(404)
    if not can_delete_case(current_user, c):
        flash("No permission to delete.", "error")
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
        flash("Password required (min 6 chars).", "error")
        return redirect(url_for("case_detail", cid=cid))

    pdf_bytes = build_pdf(c, template=form.template.data)

    attachments = []
    if form.template.data == "full":
        for u in c.updates:
            for m in u.photos:
                if m.kind == "voice" or (m.kind != "photo" and m.data):
                    attachments.append({
                        "name": m.filename or f"memo_{m.id}.bin",
                        "data": m.data,
                    })

    try:
        encrypted_pdf = encrypt_pdf_with_attachments(
            pdf_bytes, form.password.data, attachments
        )
    except Exception as e:
        flash(f"Encryption failed: {e}", "error")
        return redirect(url_for("case_detail", cid=cid))

    audit("report_download",
          f"Case #{cid} — template={form.template.data}",
          actor=current_user.username)

    safe_title = "".join(ch for ch in c.title if ch.isalnum() or ch in "-_")[:40] or "case"
    fname = f"MIS_{safe_title}_{form.template.data}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"

    resp = send_file(io.BytesIO(encrypted_pdf), mimetype="application/pdf",
                     as_attachment=True, download_name=fname)
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ============================================================
# ROUTES — UPDATE EDIT / DELETE
# ============================================================
@app.route("/updates/<int:uid>/edit", methods=["GET", "POST"])
@login_required
def update_edit(uid):
    u = db.session.get(Update, uid) or abort(404)
    case = u.case
    if not can_write_case(current_user, case):
        abort(403)

    form = QuickAddForm(obj=u)
    form.case_id.choices = case_choices()
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
                                data=raw, sha256=sha256_bytes(raw),
                            ))
        u.integrity_hash = compute_integrity(u, extra=u.body_enc[:32])
        db.session.commit()
        flash("Entry updated.", "success")
        return redirect(url_for("case_detail", cid=u.case_id))
    return render_template("update_edit.html", form=form, update=u)


@app.route("/updates/<int:uid>/delete", methods=["POST"])
@login_required
def update_delete(uid):
    u = db.session.get(Update, uid) or abort(404)
    case = u.case
    if not can_write_case(current_user, case):
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
    if not can_write_case(current_user, m.update.case):
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
# ROUTES — PEOPLE
# ============================================================
@app.route("/entities", methods=["GET", "POST"])
@login_required
def entities():
    form = EntityForm()
    if form.validate_on_submit():
        e = Entity(name=form.name.data, type=form.type.data, region=form.region.data or "")
        e.notes = form.notes.data or ""
        try:
            if form.latitude.data:
                e.latitude = float(form.latitude.data)
            if form.longitude.data:
                e.longitude = float(form.longitude.data)
        except Exception:
            pass
        db.session.add(e)
        db.session.commit()
        flash("Entity recorded.", "success")
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
@require_role("admin", "manager")
def entity_delete(eid):
    ok, err = delete_entity_and_children(eid)
    if not ok:
        flash(f"Delete failed: {err}", "error")
    return redirect(url_for("entities"))


@app.route("/cases/<int:cid>/entities", methods=["POST"])
@login_required
def case_entity_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    if not can_write_case(current_user, c):
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
    if not can_write_case(current_user, link.case):
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
    if not can_write_case(current_user, link.case):
        abort(403)
    cid = link.case_id
    db.session.delete(link)
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
            flash("Cannot self-link.", "error")
        else:
            r = Relationship(
                from_id=form.from_id.data, to_id=form.to_id.data,
                relation=form.relation.data,
            )
            r.description = form.description.data or ""
            db.session.add(r)
            db.session.commit()
            flash("Link recorded.", "success")
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
            db.select(Case).where(or_(Case.title.ilike(like), Case.subject.ilike(like)))
        ).scalars().all()
        all_updates = db.session.execute(db.select(Update)).scalars().all()
        results["updates"] = [u for u in all_updates if q.lower() in (u.body or "").lower()][:100]
        all_entities = db.session.execute(db.select(Entity)).scalars().all()
        results["entities"] = [e for e in all_entities if q.lower() in (e.name or "").lower() or q.lower() in (e.notes or "").lower()][:100]
    return render_template("search.html", q=q, results=results)


@app.route("/activity")
@login_required
@require_role("admin", "manager")
def activity():
    rows = db.session.execute(
        db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(300)
    ).scalars().all()
    return render_template("audit.html", entries=rows)


# ============================================================
# ROUTES — TIMED NOTES
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
# ROUTES — BRIEFING
# ============================================================
@app.route("/briefing")
@login_required
def briefing():
    days = int(request.args.get("days", 1))
    since = datetime.now() - timedelta(days=days)
    updates = db.session.execute(
        db.select(Update).where(Update.happened_at >= since)
        .order_by(Update.happened_at.desc())
    ).scalars().all()
    return render_template("briefing.html", days=days, since=since, updates=updates)


# ============================================================
# ROUTES — MAP VIEW
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
                "lat": p.latitude, "lng": p.longitude,
                "verified": p.verified,
                "color": {"LOW": "#3fb950", "MEDIUM": "#ffb000",
                          "HIGH": "#ff7b00", "CRITICAL": "#ff3b30"}.get(p.threat_level, "#8a8577"),
            })
    return render_template("map.html", markers=markers)


# ============================================================
# ROUTES — TIMELINE VISUALIZATION
# ============================================================
@app.route("/cases/<int:cid>/timeline-viz")
@login_required
def timeline_viz(cid):
    c = db.session.get(Case, cid) or abort(404)
    if not can_view_case(current_user, c):
        abort(403)
    events = []
    for u in c.updates:
        events.append({
            "id": u.id,
            "when": u.happened_at.strftime("%Y-%m-%d %H:%M"),
            "ts": u.happened_at.timestamp(),
            "body": (u.body or "")[:100],
            "media": len(u.photos),
            "photos": sum(1 for m in u.photos if m.kind == "photo"),
            "voices": sum(1 for m in u.photos if m.kind == "voice"),
        })
    return render_template("timeline_viz.html", case=c, events=events)


# ============================================================
# ROUTES — BACKUPS
# ============================================================
@app.route("/backups")
@login_required
@require_role("admin")
def backups():
    rows = db.session.execute(db.select(Backup).order_by(Backup.created_at.desc())).scalars().all()
    return render_template("backups.html", backups=rows)


@app.route("/backups/create", methods=["POST"])
@login_required
@require_role("admin")
def backup_create():
    password = (request.form.get("password") or "").strip()
    if len(password) < 8:
        flash("Backup password must be at least 8 characters.", "error")
        return redirect(url_for("backups"))

    data = {
        "created_at": datetime.utcnow().isoformat(),
        "cases": [],
        "users_count": db.session.scalar(db.select(db.func.count(User.id))) or 0,
    }
    for c in db.session.execute(db.select(Case)).scalars().all():
        case_data = {
            "id": c.id, "title": c.title, "subject": c.subject,
            "notes": c.notes, "status": c.status, "priority": c.priority,
            "threat_level": c.threat_level,
            "updates": []
        }
        for u in c.updates:
            case_data["updates"].append({
                "when": u.happened_at.isoformat(),
                "body": u.body,
                "media_count": len(u.photos),
            })
        data["cases"].append(case_data)

    raw = json.dumps(data, indent=2).encode("utf-8")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = hashlib.sha256(password.encode()).digest()
    ct = AESGCM(key).encrypt(nonce, raw, associated_data=b"MIS_BACKUP")
    blob = b"MISB1" + salt + nonce + ct

    fname = f"MIS_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.misbak"
    rec = Backup(filename=fname, size_bytes=len(blob), record_count=len(data["cases"]),
                 created_by=current_user.username)
    db.session.add(rec)
    db.session.commit()
    audit("backup_create", fname, actor=current_user.username)

    resp = send_file(io.BytesIO(blob), mimetype="application/octet-stream",
                     as_attachment=True, download_name=fname)
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    return resp


# ============================================================
# ROUTES — INTEGRITY
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
# ROUTES — USERS
# ============================================================
@app.route("/users", methods=["GET", "POST"])
@login_required
@require_role("admin")
def users():
    form = UserForm()
    if form.validate_on_submit():
        uname = form.username.data.strip()
        if db.session.execute(db.select(User).filter_by(username=uname)).scalar():
            flash("Username taken.", "error")
        else:
            u = User(username=uname, codename=form.codename.data or "",
                     email=form.email.data or "", role=form.role.data,
                     clearance=form.clearance.data)
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
@require_role("admin")
def user_delete(uid):
    if uid == current_user.id:
        flash("Cannot delete yourself.", "error")
        return redirect(url_for("users"))
    u = db.session.get(User, uid) or abort(404)
    db.session.delete(u)
    db.session.commit()
    return redirect(url_for("users"))


# ============================================================
# PWA headers
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
            user = User(username=u, codename="ALPHA", role="admin", clearance="EYES_ONLY")
            user.set_password(p)
            db.session.add(user)
            db.session.commit()
            print(f"🔥 Force-reseeded user: {u}")
            return

        if not existing:
            user = User(username=u, codename="ALPHA", role="admin", clearance="EYES_ONLY")
            user.set_password(p)
            db.session.add(user)
            db.session.commit()
            print(f"✅ Seeded user: {u}")
        else:
            if not existing.role:
                existing.role = "admin"
                db.session.commit()
            print(f"✅ User {u} OK")


bootstrap()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
