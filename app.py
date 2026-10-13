# ============================================================
# MIS v20 — Wave 4: Dead Man's Switch + Structured Exports + PWA
# Base: v19 (Wave 3 working, duress sandbox locked)
# ============================================================

import os, io, json, hmac, hashlib, secrets, base64, re, subprocess, tempfile, threading, csv, zipfile
from datetime import datetime, timedelta
from functools import wraps
from collections import Counter, defaultdict

from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, send_file, abort, jsonify, session, Response
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
    BooleanField, SubmitField, DateTimeField, IntegerField
)
from wtforms.validators import DataRequired, Length, EqualTo, Optional, Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy import or_, text, inspect

import networkx as nx
import requests

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
    if _db.startswith("postgresql://") and "+psycopg" not in _db:
        _db = _db.replace("postgresql://", "postgresql+psycopg2://", 1)
    SQLALCHEMY_DATABASE_URI = _db
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 300}
    WTF_CSRF_TIME_LIMIT = None
    MAX_CONTENT_LENGTH = 80 * 1024 * 1024
    INITIAL_USERNAME = os.getenv("INITIAL_USERNAME", "Mpc")
    INITIAL_PASSWORD = os.getenv("INITIAL_PASSWORD", "08800Mpc!")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_IDLE_TIMEOUT = timedelta(minutes=30)
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")


app = Flask(__name__)
app.config.from_object(Config)

from flask_wtf.csrf import generate_csrf

@app.context_processor
def _inject_csrf():
    return {"csrf_token": generate_csrf}

@app.context_processor
def _inject_now():
    return {"now_local_str": datetime.now().strftime("%Y-%m-%dT%H:%M")}

@app.context_processor
def _inject_duress():
    return {"duress_mode": bool(session.get("duress"))}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in."


# ============================================================
# CRYPTO (same as v19)
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


def new_case_key():
    return secrets.token_bytes(32)


def wrap_case_key(case_key):
    try:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(get_master_key()).encrypt(nonce, case_key,
                                              associated_data=b"MIS_CASEKEY")
        return base64.b64encode(b"CK01" + nonce + ct).decode("ascii")
    except Exception as e:
        print(f"⚠️  wrap_case_key failed: {e}")
        return ""


def unwrap_case_key(wrapped_b64):
    if not wrapped_b64:
        return None
    try:
        blob = base64.b64decode(wrapped_b64, validate=True)
        if blob[:4] != b"CK01":
            return None
        nonce, ct = blob[4:16], blob[16:]
        return AESGCM(get_master_key()).decrypt(nonce, ct,
                                                associated_data=b"MIS_CASEKEY")
    except Exception as e:
        print(f"⚠️  unwrap_case_key failed: {e}")
        return None


def case_encrypt(case, plaintext):
    if not plaintext:
        return ""
    if case is None:
        return field_encrypt(plaintext)
    key = unwrap_case_key(case.case_key_wrapped or "")
    if not key:
        return field_encrypt(plaintext)
    try:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"),
                                 associated_data=b"MIS_CASEDATA")
        return base64.b64encode(b"CD01" + nonce + ct).decode("ascii")
    except Exception:
        return plaintext


def case_decrypt(case, stored):
    if not stored:
        return ""
    if case is None:
        return field_decrypt(stored)
    try:
        blob = base64.b64decode(stored, validate=True)
        if blob[:4] != b"CD01":
            return field_decrypt(stored)
        key = unwrap_case_key(case.case_key_wrapped)
        if not key:
            return "[cannot decrypt — case key missing]"
        nonce, ct = blob[4:16], blob[16:]
        return AESGCM(key).decrypt(nonce, ct,
                                   associated_data=b"MIS_CASEDATA").decode("utf-8")
    except Exception:
        return field_decrypt(stored)


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
# KEYWORD INDEX
# ============================================================
STOPWORDS = set("""
a an the and or but if then else of in on at to for from with by is are was were be been
being have has had do does did this that these those it its i you he she we they them
his her him us our your my their as not no yes very more most some any all
""".split())


def extract_keywords(text_value):
    if not text_value:
        return set()
    words = re.findall(r"[A-Za-z][A-Za-z0-9'-]{2,}", text_value.lower())
    return {w for w in words if w not in STOPWORDS and len(w) >= 3}


def keyword_hash(word):
    return hmac.new(get_master_key(), word.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


def index_text(source_type, source_id, plain_text, case_id=None):
    SearchIndex.query.filter_by(source_type=source_type, source_id=source_id).delete()
    for word in extract_keywords(plain_text):
        db.session.add(SearchIndex(
            source_type=source_type,
            source_id=source_id,
            case_id=case_id,
            kw_hash=keyword_hash(word),
        ))


# ============================================================
# TRANSCRIPTION (unchanged)
# ============================================================
def _bg_transcribe(app_ctx, media_id, case_id):
    with app_ctx:
        try:
            m = db.session.get(UpdateMedia, media_id)
            if not m or m.transcript:
                return
            if not m.data or len(m.data) < 100:
                m.transcript = "[empty or too short]"
                m.transcribed_at = datetime.utcnow()
                db.session.commit()
                return
            txt = transcribe_audio(m.data, m.mimetype or "audio/webm")
            m.transcript = txt or "[transcription failed]"
            m.transcribed_at = datetime.utcnow()
            db.session.commit()
            if txt:
                index_text("voice", m.id, txt, case_id=case_id)
                db.session.commit()
        except Exception as e:
            print(f"⚠️  background transcription failed: {e}")


def spawn_transcription(media_id, case_id):
    try:
        ctx = app.app_context()
        t = threading.Thread(target=_bg_transcribe, args=(ctx, media_id, case_id), daemon=True)
        t.start()
    except Exception as e:
        print(f"⚠️  could not spawn transcription: {e}")


def transcribe_audio(audio_bytes, mime_hint="audio/webm"):
    tmp_in = None
    tmp_wav = None
    try:
        ext = ".webm"
        if "wav" in mime_hint:
            ext = ".wav"
        elif "mpeg" in mime_hint or "mp3" in mime_hint:
            ext = ".mp3"
        elif "ogg" in mime_hint:
            ext = ".ogg"
        elif "mp4" in mime_hint or "m4a" in mime_hint:
            ext = ".m4a"
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as f:
            f.write(audio_bytes)
            tmp_in = f.name
        tmp_wav = tmp_in + ".wav"
        try:
            from pydub import AudioSegment
            seg = AudioSegment.from_file(tmp_in)
            seg.export(tmp_wav, format="wav")
        except Exception as e:
            print(f"⚠️  pydub convert failed: {e}")
            tmp_wav = tmp_in
        import speech_recognition as sr
        r = sr.Recognizer()
        with sr.AudioFile(tmp_wav) as source:
            audio_data = r.record(source)
        try:
            return r.recognize_google(audio_data) or ""
        except sr.UnknownValueError:
            return "[transcript unavailable — audio not clear]"
        except sr.RequestError as e:
            print(f"⚠️  SR request error: {e}")
            return "[transcript service unavailable]"
    except Exception as e:
        print(f"⚠️  transcribe_audio failed: {e}")
        return ""
    finally:
        for p in (tmp_in, tmp_wav):
            try:
                if p and os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass


# ============================================================
# ROLES + MODELS
# ============================================================
ROLE_TOP = "top_secret"
ROLE_AGENT = "agent"
ROLE_ANALYST = "analyst"

ROLE_LABELS = [
    (ROLE_TOP, "Top Secret"),
    (ROLE_AGENT, "Agent"),
    (ROLE_ANALYST, "Analyst"),
]


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
    duress_hash = db.Column(db.String(255), default="")
    duress_contact = db.Column(db.String(200), default="")
    duress_triggered_at = db.Column(db.DateTime, nullable=True)
    # ---- Wave 4: Dead Man's Switch ----
    deadman_enabled = db.Column(db.Boolean, default=False)
    deadman_days = db.Column(db.Integer, default=7)         # check-in window
    deadman_message = db.Column(db.Text, default="")         # note to contact
    deadman_last_checkin = db.Column(db.DateTime, nullable=True)
    deadman_fired_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw, method="pbkdf2:sha256", salt_length=16)

    def set_duress(self, raw):
        if not raw:
            self.duress_hash = ""
        else:
            self.duress_hash = generate_password_hash(raw, method="pbkdf2:sha256", salt_length=16)

    def check_password(self, raw):
        h = (self.password_hash or "").strip()
        if not h or ":" not in h:
            return False
        try:
            return check_password_hash(h, raw)
        except Exception:
            return False

    def check_duress(self, raw):
        h = (self.duress_hash or "").strip()
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

    def deadman_status(self):
        if not self.deadman_enabled:
            return "off"
        if self.deadman_fired_at:
            return "fired"
        last = self.deadman_last_checkin or self.created_at
        elapsed = (datetime.utcnow() - last).days
        if elapsed >= self.deadman_days:
            return "overdue"
        return "ok"

    def deadman_days_left(self):
        last = self.deadman_last_checkin or self.created_at
        remaining = self.deadman_days - (datetime.utcnow() - last).days
        return max(0, remaining)

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
    is_duress = db.Column(db.Boolean, default=False)


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
    case_key_wrapped = db.Column(db.Text, default="")
    key_rotated_at = db.Column(db.DateTime, nullable=True)
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
    def notes(self):
        return case_decrypt(self, self.notes_enc or "")

    @notes.setter
    def notes(self, v):
        self.notes_enc = case_encrypt(self, v or "")

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
    def body(self):
        return case_decrypt(self.case, self.body_enc or "")

    @body.setter
    def body(self, v):
        self.body_enc = case_encrypt(self.case, v or "")


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
        return case_decrypt(self.case, self.body_enc or "")

    @body.setter
    def body(self, v):
        self.body_enc = case_encrypt(self.case, v or "")


class UpdateMedia(db.Model):
    __tablename__ = "mis_update_media"
    id = db.Column(db.Integer, primary_key=True)
    update_id = db.Column(db.Integer, db.ForeignKey("mis_updates.id"), nullable=False)
    kind = db.Column(db.String(20), default="photo")
    filename = db.Column(db.String(255))
    mimetype = db.Column(db.String(120), default="application/octet-stream")
    data = db.Column(db.LargeBinary)
    sha256 = db.Column(db.String(64))
    transcript = db.Column(db.Text, default="")
    transcribed_at = db.Column(db.DateTime, nullable=True)
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
    merged_into_id = db.Column(db.Integer, nullable=True)
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


class SearchIndex(db.Model):
    __tablename__ = "mis_search_index"
    id = db.Column(db.Integer, primary_key=True)
    source_type = db.Column(db.String(40), index=True)
    source_id = db.Column(db.Integer, index=True)
    case_id = db.Column(db.Integer, index=True, nullable=True)
    kw_hash = db.Column(db.String(32), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CustodyLog(db.Model):
    __tablename__ = "mis_custody_log"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, index=True, nullable=False)
    action = db.Column(db.String(60), index=True)
    detail = db.Column(db.Text)
    actor = db.Column(db.String(80), index=True)
    actor_role = db.Column(db.String(20))
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(300))
    prev_hash = db.Column(db.String(64), index=True)
    entry_hash = db.Column(db.String(64), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class APIKey(db.Model):
    """Wave 4: API keys for external read access."""
    __tablename__ = "mis_api_keys"
    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(64), unique=True, index=True)
    label = db.Column(db.String(80), default="")
    role = db.Column(db.String(20), default=ROLE_ANALYST)
    created_by = db.Column(db.String(80), default="system")
    last_used = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def custody(case_id, action, detail=""):
    try:
        last = db.session.execute(
            db.select(CustodyLog).where(CustodyLog.case_id == case_id)
            .order_by(CustodyLog.id.desc()).limit(1)
        ).scalar()
        prev_hash = last.entry_hash if last else ("0" * 64)
        actor = current_user.username if current_user.is_authenticated else "system"
        actor_role = current_user.role if current_user.is_authenticated else "system"
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")[:60]
        ua = (request.headers.get("User-Agent", "") or "")[:280]
        payload = "|".join([str(case_id), action, detail or "",
                            actor, actor_role, ip, prev_hash])
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        entry = CustodyLog(
            case_id=case_id, action=action, detail=detail,
            actor=actor, actor_role=actor_role, ip=ip, user_agent=ua,
            prev_hash=prev_hash, entry_hash=entry_hash,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"⚠️  custody log failed: {e}")


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
        ("duress_hash", "VARCHAR(255) DEFAULT ''"),
        ("duress_contact", "VARCHAR(200) DEFAULT ''"),
        ("duress_triggered_at", "TIMESTAMP"),
        ("deadman_enabled", "BOOLEAN DEFAULT FALSE"),
        ("deadman_days", "INTEGER DEFAULT 7"),
        ("deadman_message", "TEXT DEFAULT ''"),
        ("deadman_last_checkin", "TIMESTAMP"),
        ("deadman_fired_at", "TIMESTAMP"),
    ],
    "mis_sessions": [("is_duress", "BOOLEAN DEFAULT FALSE")],
    "mis_cases": [
        ("subject", "VARCHAR(200) DEFAULT ''"),
        ("notes_enc", "TEXT DEFAULT ''"),
        ("threat_level", "VARCHAR(20) DEFAULT 'MEDIUM'"),
        ("priority", "INTEGER DEFAULT 3"),
        ("due_date", "TIMESTAMP"),
        ("assigned_agent_id", "INTEGER"),
        ("integrity_hash", "VARCHAR(64) DEFAULT ''"),
        ("case_key_wrapped", "TEXT DEFAULT ''"),
        ("key_rotated_at", "TIMESTAMP"),
        ("created_by", "VARCHAR(80) DEFAULT 'system'"),
    ],
    "mis_updates": [
        ("body_enc", "TEXT DEFAULT ''"),
        ("integrity_hash", "VARCHAR(64) DEFAULT ''"),
    ],
    "mis_update_media": [
        ("transcript", "TEXT DEFAULT ''"),
        ("transcribed_at", "TIMESTAMP"),
    ],
    "mis_entities": [
        ("notes_enc", "TEXT DEFAULT ''"),
        ("verified", "BOOLEAN DEFAULT FALSE"),
        ("threat_level", "VARCHAR(20) DEFAULT 'LOW'"),
        ("region", "VARCHAR(120) DEFAULT ''"),
        ("latitude", "DOUBLE PRECISION DEFAULT 0"),
        ("longitude", "DOUBLE PRECISION DEFAULT 0"),
        ("merged_into_id", "INTEGER"),
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
# DURESS SANDBOX
# ============================================================
DURESS_ALLOWED_ENDPOINTS = {
    "login", "logout", "static", "duress_home",
    "manifest", "service_worker", "offline",
}


@app.before_request
def _enforce_duress_sandbox():
    if not session.get("duress"):
        return
    endpoint = request.endpoint or ""
    if endpoint in DURESS_ALLOWED_ENDPOINTS:
        return
    if request.method == "POST":
        flash("Saved.", "success")
    return redirect(url_for("duress_home"))


def is_duress_session():
    return bool(session.get("duress"))


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
                ("mis_search_index", "case_id"),
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
            conn.execute(text("DELETE FROM mis_search_index WHERE source_type = 'update' AND source_id = :uid"), {"uid": uid})
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


class DuressForm(FlaskForm):
    duress_password = PasswordField("Duress password (leave blank to disable)")
    duress_contact = StringField("Alert email (optional)", validators=[Optional(), Length(0, 200)])
    current_password = PasswordField("Your current password", validators=[DataRequired()])
    submit = SubmitField("Update Duress Settings")


class DeadManForm(FlaskForm):
    enabled = BooleanField("Enable Dead Man's Switch")
    days = IntegerField("Check-in interval (days)", default=7)
    message = TextAreaField("Message to send (optional)")
    current_password = PasswordField("Your current password", validators=[DataRequired()])
    submit = SubmitField("Save Dead Man's Switch")


class ExportForm(FlaskForm):
    format = SelectField("Format", choices=[
        ("json", "JSON"),
        ("csv", "CSV (zip of tables)"),
        ("kml", "KML (Google Earth)"),
        ("stix", "STIX 2.1 (JSON)"),
    ], default="json")
    scope = SelectField("Scope", choices=[
        ("all", "All cases I can see"),
        ("single", "Single case"),
    ], default="all")
    case_id = SelectField("Case (if single)", coerce=int, validators=[Optional()])
    submit = SubmitField("Download Export")


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
    rows = db.session.execute(
        db.select(Entity).where(Entity.merged_into_id == None).order_by(Entity.name)
    ).scalars().all()
    return [(e.id, f"{e.name} ({e.type})") for e in rows]


def user_choices():
    rows = db.session.execute(db.select(User).order_by(User.username)).scalars().all()
    return [(u.id, u.username) for u in rows]


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def esc(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ============================================================
# WAVE 4: TELEGRAM ALERT
# ============================================================
def send_telegram_alert(text):
    token = app.config.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = app.config.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat:
        print("⚠️  Telegram not configured — logging alert only")
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat, "text": text, "parse_mode": "Markdown"},
            timeout=10,
        )
        return r.status_code == 200
    except Exception as e:
        print(f"⚠️  Telegram alert failed: {e}")
        return False


def check_deadman_switches():
    """Called on every login — fires any overdue switches."""
    try:
        now = datetime.utcnow()
        users = db.session.execute(
            db.select(User).where(User.deadman_enabled == True)
        ).scalars().all()
        for u in users:
            if u.deadman_fired_at:
                continue
            last = u.deadman_last_checkin or u.created_at
            elapsed = (now - last).days
            if elapsed >= (u.deadman_days or 7):
                # Fire!
                msg = (
                    f"⚠️ *MIS Dead Man's Switch fired*\n"
                    f"User *{u.username}* hasn't checked in for "
                    f"{elapsed} days (limit: {u.deadman_days}).\n"
                    f"Last check-in: {last.strftime('%Y-%m-%d %H:%M')} UTC\n"
                )
                if u.deadman_message:
                    msg += f"\nMessage: {u.deadman_message}"
                send_telegram_alert(msg)
                u.deadman_fired_at = now
                db.session.commit()
                audit("deadman_fired", f"{u.username} overdue {elapsed}d", actor="system")
    except Exception as e:
        print(f"⚠️  deadman check failed: {e}")


# ============================================================
# PDF (unchanged)
# ============================================================
def build_pdf(case, template="full", include_custody=False):
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
                            if m.transcript:
                                story.append(Paragraph(f"Transcript: {esc(m.transcript)}", meta))
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

    if include_custody:
        story.append(PageBreak())
        story.append(Paragraph("Chain of Custody", h2))
        entries = db.session.execute(
            db.select(CustodyLog).where(CustodyLog.case_id == case.id)
            .order_by(CustodyLog.id.asc())
        ).scalars().all()
        if entries:
            data = [["When", "Action", "Actor", "Role", "IP"]]
            for e in entries:
                data.append([
                    e.created_at.strftime("%d %b %Y %H:%M"),
                    e.action, e.actor, e.actor_role or "", e.ip or ""
                ])
            t = Table(data, colWidths=[3.5*cm, 2.5*cm, 3*cm, 2.5*cm, 4*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("— no custody entries yet —", body))

    doc.build(story)
    return buf.getvalue()


def encrypt_pdf_with_attachments(pdf_bytes, password, attachments):
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
        writer.encrypt(user_password=password, owner_password=password,
                       permissions_flag=-1, algorithm="AES-256")
        out = io.BytesIO()
        writer.write(out)
        blob = out.getvalue()
        try:
            verify = PdfReader(io.BytesIO(blob))
            if verify.is_encrypted:
                try:
                    r = verify.decrypt("")
                    if r != 0:
                        return _encrypt_pdf_fallback(pdf_bytes, password, attachments)
                except Exception:
                    pass
            return blob
        except Exception:
            return blob
    except Exception as e:
        print(f"⚠️  Primary PDF encrypt failed: {e}")
        return _encrypt_pdf_fallback(pdf_bytes, password, attachments)


def _encrypt_pdf_fallback(pdf_bytes, password, attachments):
    for algorithm in ("AES-256", "AES-128", "RC4-128"):
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
            writer.encrypt(user_password=password, owner_password=password,
                           permissions_flag=-1, algorithm=algorithm)
            out = io.BytesIO()
            writer.write(out)
            blob = out.getvalue()
            v = PdfReader(io.BytesIO(blob))
            if v.is_encrypted:
                try:
                    r = v.decrypt("")
                    if r == 0:
                        continue
                except Exception:
                    return blob
            else:
                continue
            return blob
        except Exception as e:
            print(f"⚠️  Fallback {algorithm} failed: {e}")
    return pdf_bytes


def make_encrypted_backup(password):
    data = {"created_at": datetime.utcnow().isoformat(), "cases": []}
    for c in db.session.execute(db.select(Case)).scalars().all():
        cd = {"id": c.id, "title": c.title, "subject": c.subject, "notes": c.notes,
              "status": c.status, "priority": c.priority, "threat_level": c.threat_level,
              "updates": []}
        for u in c.updates:
            cd["updates"].append({"when": u.happened_at.isoformat(), "body": u.body,
                                  "media_count": len(u.photos)})
        data["cases"].append(cd)
    header = {"product": "MIS", "format": "misbak-v1", "algorithm": "AES-256-GCM",
              "key_derivation": "SHA-256(password+salt)", "created_at": data["created_at"],
              "case_count": len(data["cases"])}
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
# WAVE 4: EXPORTERS
# ============================================================
def export_json(cases, user):
    """Full JSON export — everything readable by the user."""
    out = {
        "product": "MIS",
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "exported_by": user.username,
        "case_count": len(cases),
        "cases": [],
    }
    for c in cases:
        cd = {
            "id": c.id,
            "title": c.title,
            "subject": c.subject,
            "notes": c.notes,
            "status": c.status,
            "priority": c.priority,
            "threat_level": c.threat_level,
            "created_by": c.created_by,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "assigned_agent": c.assigned_agent.username if c.assigned_agent else None,
            "updates": [],
            "people": [],
            "analyst_notes": [],
            "custody": [],
        }
        for u in sorted(c.updates, key=lambda x: x.happened_at):
            cd["updates"].append({
                "id": u.id,
                "when": u.happened_at.isoformat(),
                "body": u.body,
                "created_by": u.created_by,
                "media": [{
                    "id": m.id, "kind": m.kind, "filename": m.filename,
                    "sha256": m.sha256, "transcript": m.transcript or "",
                } for m in u.photos],
            })
        for link in c.links:
            cd["people"].append({
                "entity_id": link.entity_id,
                "name": link.entity.name if link.entity else "?",
                "type": link.entity.type if link.entity else "",
                "region": link.entity.region if link.entity else "",
                "role": link.role,
                "note": link.note,
            })
        for n in c.analyst_notes:
            cd["analyst_notes"].append({
                "id": n.id, "category": n.category, "title": n.title,
                "body": n.body, "created_by": n.created_by,
                "created_at": n.created_at.isoformat(),
            })
        for cl in db.session.execute(
            db.select(CustodyLog).where(CustodyLog.case_id == c.id).order_by(CustodyLog.id)
        ).scalars().all():
            cd["custody"].append({
                "when": cl.created_at.isoformat(),
                "action": cl.action, "detail": cl.detail,
                "actor": cl.actor, "ip": cl.ip,
                "entry_hash": cl.entry_hash,
            })
        out["cases"].append(cd)
    return json.dumps(out, indent=2, ensure_ascii=False).encode("utf-8")


def export_csv_zip(cases, user):
    """CSV export as a zip of tables."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # cases.csv
        sio = io.StringIO()
        w = csv.writer(sio)
        w.writerow(["id", "title", "subject", "status", "priority",
                    "threat_level", "assigned_agent", "created_by", "created_at"])
        for c in cases:
            w.writerow([c.id, c.title, c.subject, c.status, c.priority,
                        c.threat_level,
                        c.assigned_agent.username if c.assigned_agent else "",
                        c.created_by,
                        c.created_at.isoformat() if c.created_at else ""])
        z.writestr("cases.csv", sio.getvalue())

        # updates.csv
        sio = io.StringIO()
        w = csv.writer(sio)
        w.writerow(["case_id", "update_id", "when", "body", "created_by", "media_count"])
        for c in cases:
            for u in c.updates:
                w.writerow([c.id, u.id, u.happened_at.isoformat(),
                            u.body, u.created_by, len(u.photos)])
        z.writestr("updates.csv", sio.getvalue())

        # people.csv
        sio = io.StringIO()
        w = csv.writer(sio)
        w.writerow(["case_id", "entity_id", "name", "type", "role", "region", "note"])
        for c in cases:
            for link in c.links:
                w.writerow([c.id, link.entity_id,
                            link.entity.name if link.entity else "",
                            link.entity.type if link.entity else "",
                            link.role,
                            link.entity.region if link.entity else "",
                            link.note])
        z.writestr("people.csv", sio.getvalue())

        # analyst_notes.csv
        sio = io.StringIO()
        w = csv.writer(sio)
        w.writerow(["case_id", "id", "category", "title", "body", "created_by", "created_at"])
        for c in cases:
            for n in c.analyst_notes:
                w.writerow([c.id, n.id, n.category, n.title, n.body,
                            n.created_by, n.created_at.isoformat()])
        z.writestr("analyst_notes.csv", sio.getvalue())

        # custody.csv
        sio = io.StringIO()
        w = csv.writer(sio)
        w.writerow(["case_id", "id", "when", "action", "detail", "actor", "ip", "entry_hash"])
        for c in cases:
            for cl in db.session.execute(
                db.select(CustodyLog).where(CustodyLog.case_id == c.id).order_by(CustodyLog.id)
            ).scalars().all():
                w.writerow([c.id, cl.id, cl.created_at.isoformat(),
                            cl.action, cl.detail, cl.actor, cl.ip, cl.entry_hash])
        z.writestr("custody.csv", sio.getvalue())

    return buf.getvalue()


def export_kml(cases, user):
    """KML for Google Earth / Google Maps."""
    def esc_xml(s):
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<kml xmlns="http://www.opengis.net/kml/2.2">',
             '<Document>',
             f'<name>MIS Export</name>',
             f'<description>Exported {datetime.utcnow().isoformat()}Z by {user.username}</description>']

    # Color by threat
    colors = {"LOW": "ff50b93f", "MEDIUM": "ff00b0ff",
              "HIGH": "ff007bff", "CRITICAL": "ff303bff"}  # ABGR order

    # Style for each threat level
    for level, color in colors.items():
        lines.append(f'<Style id="threat-{level}">')
        lines.append('<IconStyle><color>' + color + '</color>'
                     '<scale>1.1</scale>'
                     '<Icon><href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href></Icon>'
                     '</IconStyle></Placemark>'.replace('</Placemark>', ''))
        lines.append('</Style>')

    # Entities with coordinates
    entities_seen = set()
    for c in cases:
        for link in c.links:
            e = link.entity
            if not e or e.id in entities_seen:
                continue
            entities_seen.add(e.id)
            if not e.latitude or not e.longitude:
                continue
            lines.append('<Placemark>')
            lines.append(f'<name>{esc_xml(e.name)}</name>')
            desc = f"Type: {esc_xml(e.type)}\nRegion: {esc_xml(e.region)}\n"
            desc += f"Threat: {esc_xml(e.threat_level)}\n"
            desc += f"Role on case: {esc_xml(link.role)}\n"
            if link.note:
                desc += f"Note: {esc_xml(link.note)}\n"
            lines.append(f'<description>{esc_xml(desc)}</description>')
            lines.append(f'<styleUrl>#threat-{e.threat_level}</styleUrl>')
            lines.append(f'<Point><coordinates>{e.longitude},{e.latitude},0</coordinates></Point>')
            lines.append('</Placemark>')

    lines.append('</Document>')
    lines.append('</kml>')
    return "\n".join(lines).encode("utf-8")


def export_stix(cases, user):
    """Minimal STIX 2.1 bundle: each case is an incident, each entity is an identity."""
    bundle_id = f"bundle--{secrets.token_hex(16)}"
    objects = []
    now_iso = datetime.utcnow().isoformat() + "Z"

    for c in cases:
        # Case = incident
        incident_id = f"incident--{secrets.token_hex(16)}"
        objects.append({
            "type": "incident",
            "spec_version": "2.1",
            "id": incident_id,
            "created": c.created_at.isoformat() + "Z" if c.created_at else now_iso,
            "modified": now_iso,
            "name": c.title,
            "description": f"{c.subject}\n\n{c.notes}"[:1000],
            "labels": [c.threat_level.lower(), c.status.lower()],
        })
        # Entities = identities
        for link in c.links:
            e = link.entity
            if not e:
                continue
            ident_id = f"identity--{secrets.token_hex(16)}"
            objects.append({
                "type": "identity",
                "spec_version": "2.1",
                "id": ident_id,
                "created": e.created_at.isoformat() + "Z" if e.created_at else now_iso,
                "modified": now_iso,
                "name": e.name,
                "identity_class": e.type.lower(),
                "description": f"{e.region or ''}\n{link.note}",
            })
        # Updates = observed-data
        for u in c.updates:
            obs_id = f"observed-data--{secrets.token_hex(16)}"
            objects.append({
                "type": "observed-data",
                "spec_version": "2.1",
                "id": obs_id,
                "created": u.created_at.isoformat() + "Z" if u.created_at else now_iso,
                "modified": now_iso,
                "first_observed": u.happened_at.isoformat() + "Z",
                "last_observed": u.happened_at.isoformat() + "Z",
                "number_observed": 1,
                "object_refs": [],
                "description": u.body[:500],
            })

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8")


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
        pwd = form.password.data or ""
        user = db.session.execute(db.select(User).filter_by(username=uname)).scalar()
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")

        if user and user.locked_until and user.locked_until > datetime.utcnow():
            flash(f"Account locked until {user.locked_until.strftime('%H:%M')}.", "error")
            return render_template("login.html", form=form)

        is_real = user and user.check_password(pwd)
        is_duress = (not is_real) and user and user.duress_hash and user.check_duress(pwd)

        if is_real:
            user.failed_attempts = 0
            user.locked_until = None
            user.last_ip = ip
            # Reset deadman check-in on every real login
            if user.deadman_enabled:
                user.deadman_last_checkin = datetime.utcnow()
                user.deadman_fired_at = None
            db.session.commit()
            # Fire any overdue switches for OTHER users
            check_deadman_switches()
            if user.totp_enabled:
                session["pending_2fa_user"] = user.id
                session["pending_2fa_kind"] = "real"
                return redirect(url_for("two_factor"))
            return _complete_login(user, is_duress=False)

        if is_duress:
            user.last_ip = ip
            user.duress_triggered_at = datetime.utcnow()
            db.session.commit()
            audit("duress_login", f"{user.username} used duress password", actor=user.username)
            return _complete_login(user, is_duress=True)

        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()
        audit("login_fail", f"Attempt for {uname} from {ip}")
        flash("Access denied.", "error")
    return render_template("login.html", form=form)


def _complete_login(user, is_duress=False):
    user.last_login = datetime.utcnow()
    db.session.commit()
    login_user(user)
    session.permanent = True
    session["last_seen"] = datetime.utcnow().timestamp()
    session["sid"] = secrets.token_hex(16)
    session["duress"] = bool(is_duress)
    rec = SessionRecord(user_id=user.id, session_id=session["sid"],
                        ip=user.last_ip or "",
                        user_agent=request.headers.get("User-Agent", "")[:300],
                        is_duress=is_duress)
    db.session.add(rec)
    db.session.commit()
    audit("login_success",
          f"{user.username} as {user.role}{' [DURESS]' if is_duress else ''}",
          actor=user.username)
    if is_duress:
        return redirect(url_for("duress_home"))
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
            kind = session.pop("pending_2fa_kind", "real")
            if user.deadman_enabled:
                user.deadman_last_checkin = datetime.utcnow()
                user.deadman_fired_at = None
                db.session.commit()
            return _complete_login(user, is_duress=(kind == "duress"))
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
    session.clear()
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


# ============================================================
# DURESS HOME
# ============================================================
@app.route("/duress")
def duress_home():
    fake_cases = [
        {"id": -1, "title": "Grocery list", "subject": "Personal", "items": 3},
        {"id": -2, "title": "Work meeting notes", "subject": "Office", "items": 3},
        {"id": -3, "title": "Books to read", "subject": "Personal", "items": 3},
    ]
    fake_recent = [
        "Nothing new today", "Remember to buy milk",
        "Meeting moved to 3pm", "Pay electricity bill",
    ]
    return render_template("dashboard_duress.html",
                           fake_cases=fake_cases, fake_recent=fake_recent)


# ============================================================
# DASHBOARD
# ============================================================
# ============================================================
# SETTINGS — password / 2FA / Duress / Sessions / Integrity / Activity
# ============================================================
@app.route("/settings/password", methods=["GET", "POST"])
@login_required
def change_password():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
    current_user.totp_enabled = False
    current_user.backup_codes = ""
    db.session.commit()
    flash("2FA disabled.", "success")
    return redirect(url_for("setup_2fa"))


@app.route("/settings/duress", methods=["GET", "POST"])
@login_required
def setup_duress():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    form = DuressForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "error")
        else:
            dp = (form.duress_password.data or "").strip()
            if dp and len(dp) < 6:
                flash("Duress password must be at least 6 characters.", "error")
            else:
                current_user.set_duress(dp)
                current_user.duress_contact = (form.duress_contact.data or "").strip()
                db.session.commit()
                audit("duress_updated",
                      f"duress {'set' if dp else 'cleared'}",
                      actor=current_user.username)
                flash("Duress settings updated.", "success")
                return redirect(url_for("dashboard"))
    else:
        form.duress_contact.data = current_user.duress_contact or ""
    return render_template("setup_duress.html", form=form,
                           has_duress=bool(current_user.duress_hash),
                           contact=current_user.duress_contact)


@app.route("/settings/sessions", methods=["GET", "POST"])
@login_required
def my_sessions():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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


@app.route("/integrity")
@login_required
def integrity():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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


@app.route("/activity")
@login_required
@require_role(ROLE_TOP)
def activity():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    rows = db.session.execute(
        db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(300)
    ).scalars().all()
    return render_template("audit.html", entries=rows)


@app.route("/dashboard")
@login_required
def dashboard():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    # Dead man's status for banner
    dm_status = current_user.deadman_status() if current_user.deadman_enabled else "off"
    dm_days = current_user.deadman_days_left() if current_user.deadman_enabled else 0
    return render_template("dashboard.html", cases=cases, recent=recent,
                           case_choices=case_choices_for(current_user), stats=stats,
                           now_local_str=datetime.now().strftime("%Y-%m-%dT%H:%M"),
                           agents=agents,
                           dm_status=dm_status, dm_days=dm_days)


# ============================================================
# QUICK ADD
# ============================================================
@app.route("/add", methods=["POST"])
@login_required
def quick_add():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    u.case = case
    u.body = body
    db.session.add(u)
    db.session.flush()
    u.integrity_hash = compute_integrity(u, extra=u.body_enc[:32])
    index_text("update", u.id, body, case_id=case.id)
    for kind, f in files:
        raw = f.read()
        if not raw:
            continue
        m = UpdateMedia(
            update_id=u.id, kind=kind,
            filename=secure_filename(f.filename),
            mimetype=f.mimetype or "application/octet-stream",
            data=raw, sha256=sha256_bytes(raw))
        db.session.add(m)
    db.session.commit()
    for m in u.photos:
        if m.kind == "voice":
            spawn_transcription(m.id, case.id)
    custody(case.id, "EDIT", f"Added entry: {body[:60]}")
    audit("update_add", f"Case #{u.case_id}: {body[:40]}", actor=current_user.username)
    flash("Entry logged.", "success")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/media/<int:mid>/transcribe", methods=["POST"])
@login_required
def media_transcribe(mid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    m = db.session.get(UpdateMedia, mid) or abort(404)
    if not m.update or not m.update.case:
        abort(404)
    if not can_view_case(current_user, m.update.case):
        abort(403)
    if m.kind != "voice":
        flash("Only voice memos can be transcribed.", "error")
        return redirect(request.referrer or url_for("dashboard"))
    spawn_transcription(m.id, m.update.case.id)
    flash("Transcription started. Refresh in a few seconds.", "success")
    return redirect(request.referrer or url_for("dashboard"))


# ============================================================
# CASES
# ============================================================
@app.route("/cases", methods=["GET", "POST"])
@login_required
def cases():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
        ck = new_case_key()
        c.case_key_wrapped = wrap_case_key(ck)
        c.key_rotated_at = datetime.utcnow()
        db.session.add(c)
        db.session.flush()
        c.notes = form.notes.data or ""
        c.integrity_hash = compute_integrity(c)
        index_text("case", c.id, f"{c.title} {c.subject} {c.notes}", case_id=c.id)
        db.session.commit()
        custody(c.id, "EDIT", f"Case created by {current_user.username}")
        audit("case_create", c.title, actor=current_user.username)
        flash("Case opened and assigned.", "success")
        return redirect(url_for("case_detail", cid=c.id))
    rows = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    return render_template("cases.html", form=form, cases=rows)


@app.route("/cases/<int:cid>", methods=["GET", "POST"])
@login_required
def case_detail(cid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    c = db.session.get(Case, cid) or abort(404)
    if not can_view_case(current_user, c):
        abort(403)
    try:
        if not c.case_key_wrapped:
            c.case_key_wrapped = wrap_case_key(new_case_key())
            c.key_rotated_at = datetime.utcnow()
            db.session.commit()
    except Exception as e:
        print(f"⚠️  key backfill failed: {e}")
        db.session.rollback()
    viewed_key = f"viewed_case_{cid}"
    if not session.get(viewed_key):
        custody(cid, "VIEW", "Case opened")
        session[viewed_key] = True
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
        index_text("case", c.id, f"{c.title} {c.subject} {c.notes}", case_id=c.id)
        db.session.commit()
        custody(cid, "EDIT", "Case meta updated")
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
    c = db.session.get(Case, cid) or abort(404)
    if not can_view_case(current_user, c):
        abort(403)
    form = ReportForm()
    if not form.validate_on_submit():
        flash("Password required (min 6 characters).", "error")
        return redirect(url_for("case_detail", cid=cid))
    pdf_bytes = build_pdf(c, template=form.template.data, include_custody=True)
    attachments = []
    if form.template.data == "full":
        for u in c.updates:
            for m in u.photos:
                if m.kind == "voice" or (m.kind != "photo" and m.data):
                    attachments.append({"name": m.filename or f"memo_{m.id}.bin", "data": m.data})
    encrypted_pdf = encrypt_pdf_with_attachments(pdf_bytes, form.password.data, attachments)
    custody(cid, "EXPORT", f"PDF downloaded ({form.template.data})")
    audit("report_download", f"Case #{cid} — {form.template.data}", actor=current_user.username)
    safe_title = "".join(ch for ch in c.title if ch.isalnum() or ch in "-_")[:40] or "case"
    fname = f"MIS_{safe_title}_{form.template.data}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    resp = send_file(io.BytesIO(encrypted_pdf), mimetype="application/pdf",
                     as_attachment=True, download_name=fname)
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/cases/<int:cid>/rotate-key", methods=["POST"])
@login_required
@require_role(ROLE_TOP)
def case_rotate_key(cid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    c = db.session.get(Case, cid) or abort(404)
    old_key = unwrap_case_key(c.case_key_wrapped)
    if not old_key:
        flash("No existing key to rotate.", "error")
        return redirect(url_for("case_detail", cid=cid))
    decrypted_updates = [(u, u.body) for u in c.updates]
    decrypted_notes = [(n, n.body) for n in c.analyst_notes]
    decrypted_case_notes = c.notes
    new_key = new_case_key()
    c.case_key_wrapped = wrap_case_key(new_key)
    c.key_rotated_at = datetime.utcnow()
    c.notes = decrypted_case_notes
    for u, plain in decrypted_updates:
        u.body = plain
    for n, plain in decrypted_notes:
        n.body = plain
    db.session.commit()
    custody(cid, "KEY_ROTATE", f"Key rotated by {current_user.username}")
    audit("case_key_rotate", f"Case #{cid}", actor=current_user.username)
    flash("Case key rotated. Old key is now invalid.", "success")
    return redirect(url_for("case_detail", cid=cid))


# ============================================================
# CHAIN OF CUSTODY
# ============================================================
@app.route("/cases/<int:cid>/custody")
@login_required
def case_custody(cid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    c = db.session.get(Case, cid) or abort(404)
    if not can_view_case(current_user, c):
        abort(403)
    entries = db.session.execute(
        db.select(CustodyLog).where(CustodyLog.case_id == cid)
        .order_by(CustodyLog.id.desc())
    ).scalars().all()
    chain_ok = True
    broken_at = None
    ordered = list(reversed(entries))
    prev = "0" * 64
    for e in ordered:
        expected_payload = "|".join([
            str(e.case_id), e.action, e.detail or "",
            e.actor, e.actor_role or "", e.ip or "", prev
        ])
        expected_hash = hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
        if expected_hash != e.entry_hash or e.prev_hash != prev:
            chain_ok = False
            broken_at = e.id
            break
        prev = e.entry_hash
    return render_template("custody.html", case=c, entries=entries,
                           chain_ok=chain_ok, broken_at=broken_at)


@app.route("/cases/<int:cid>/custody/add", methods=["POST"])
@login_required
def case_custody_add(cid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    c = db.session.get(Case, cid) or abort(404)
    if not can_view_case(current_user, c):
        abort(403)
    action = (request.form.get("action") or "HANDOVER").upper()
    detail = (request.form.get("detail") or "").strip()
    custody(cid, action, detail)
    flash("Custody entry recorded.", "success")
    return redirect(url_for("case_custody", cid=cid))


@app.route("/custody")
@login_required
def custody_overview():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    if current_user.role not in (ROLE_TOP, ROLE_ANALYST):
        flash("Restricted.", "error")
        return redirect(url_for("dashboard"))
    rows = db.session.execute(
        db.select(CustodyLog).order_by(CustodyLog.id.desc()).limit(200)
    ).scalars().all()
    return render_template("custody_overview.html", entries=rows)


# ============================================================
# ANALYST NOTES
# ============================================================
@app.route("/cases/<int:cid>/analyst", methods=["POST"])
@login_required
def analyst_add(cid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    c = db.session.get(Case, cid) or abort(404)
    if not can_write_analyst_note(current_user, c):
        abort(403)
    form = AnalystNoteForm()
    if form.validate_on_submit():
        n = AnalystNote(case_id=c.id, category=form.category.data,
                        title=form.title.data, created_by=current_user.username)
        n.case = c
        n.body = form.body.data
        db.session.add(n)
        db.session.flush()
        index_text("analyst_note", n.id, f"{n.title} {n.body}", case_id=c.id)
        db.session.commit()
        custody(cid, "EDIT", f"Analyst note added: {n.title[:50]}")
        audit("analyst_note_add", f"{n.category}: {n.title}", actor=current_user.username)
        flash("Analysis saved.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/analyst-notes/<int:nid>/edit", methods=["POST"])
@login_required
def analyst_note_edit(nid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    n = db.session.get(AnalystNote, nid) or abort(404)
    if n.created_by != current_user.username and current_user.role != ROLE_TOP:
        abort(403)
    n.category = request.form.get("category") or n.category
    n.title = request.form.get("title") or n.title
    n.body = request.form.get("body") or n.body
    index_text("analyst_note", n.id, f"{n.title} {n.body}", case_id=n.case_id)
    db.session.commit()
    custody(n.case_id, "EDIT", f"Analyst note updated: {n.title[:50]}")
    flash("Analysis updated.", "success")
    return redirect(url_for("case_detail", cid=n.case_id))


@app.route("/analyst-notes/<int:nid>/delete", methods=["POST"])
@login_required
def analyst_note_delete(nid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    n = db.session.get(AnalystNote, nid) or abort(404)
    if n.created_by != current_user.username and current_user.role != ROLE_TOP:
        abort(403)
    cid = n.case_id
    title = n.title
    SearchIndex.query.filter_by(source_type="analyst_note", source_id=nid).delete()
    db.session.delete(n)
    db.session.commit()
    custody(cid, "EDIT", f"Analyst note deleted: {title[:50]}")
    flash("Analysis removed.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/analyst")
@login_required
def analyst_workspace():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
                            m = UpdateMedia(
                                update_id=u.id, kind=kind,
                                filename=secure_filename(f.filename),
                                mimetype=f.mimetype or "application/octet-stream",
                                data=raw, sha256=sha256_bytes(raw))
                            db.session.add(m)
                            db.session.flush()
        u.integrity_hash = compute_integrity(u, extra=u.body_enc[:32])
        index_text("update", u.id, u.body, case_id=u.case_id)
        db.session.commit()
        for m in u.photos:
            if m.kind == "voice" and not m.transcript:
                spawn_transcription(m.id, u.case_id)
        custody(u.case_id, "EDIT", f"Entry updated: {u.body[:60]}")
        flash("Entry updated.", "success")
        return redirect(url_for("case_detail", cid=u.case_id))
    return render_template("update_edit.html", form=form, update=u)


@app.route("/updates/<int:uid>/delete", methods=["POST"])
@login_required
def update_delete(uid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    u = db.session.get(Update, uid) or abort(404)
    if not can_write_case_entries(current_user, u.case):
        abort(403)
    cid = u.case_id
    body_preview = u.body[:60] if u.body else "entry"
    ok, err = delete_update_and_children(uid)
    if not ok:
        flash(f"Delete failed: {err}", "error")
        return redirect(url_for("case_detail", cid=cid))
    custody(cid, "EDIT", f"Entry deleted: {body_preview}")
    flash("Entry deleted.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/updates/<int:uid>/media/<int:mid>/delete", methods=["POST"])
@login_required
def update_media_delete(uid, mid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    m = db.session.get(UpdateMedia, mid) or abort(404)
    if m.update_id != uid:
        abort(404)
    if not can_write_case_entries(current_user, m.update.case):
        abort(403)
    cid = m.update.case_id
    db.session.delete(m)
    db.session.commit()
    custody(cid, "EDIT", f"Media removed: {m.filename}")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/media/<int:mid>/view")
@login_required
def media_view(mid):
    if is_duress_session():
        abort(404)
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
# ENTITIES
# ============================================================
@app.route("/entities", methods=["GET", "POST"])
@login_required
def entities():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
            index_text("entity", e.id, f"{e.name} {e.notes} {e.region}")
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
            db.session.flush()
            index_text("entity", e.id, f"{e.name} {e.notes} {e.region}")
            db.session.commit()
            audit("entity_create", e.name, actor=current_user.username)
            flash("Person saved.", "success")
        return redirect(url_for("entities"))
    rows = db.session.execute(
        db.select(Entity).where(Entity.merged_into_id == None).order_by(Entity.name)
    ).scalars().all()
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
    e = db.session.get(Entity, eid) or abort(404)
    cases = db.session.execute(
        db.select(CaseEntity).where(CaseEntity.entity_id == eid)
    ).scalars().all()
    return render_template("person_detail.html", entity=e, cases=cases)


@app.route("/entities/<int:eid>/update", methods=["POST"])
@login_required
def entity_update(eid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    e = db.session.get(Entity, eid) or abort(404)
    if "region" in request.form:
        e.region = (request.form.get("region") or "").strip()
    if "notes" in request.form:
        e.notes = (request.form.get("notes") or "").strip()
    index_text("entity", e.id, f"{e.name} {e.notes} {e.region}")
    db.session.commit()
    flash("Updated.", "success")
    return redirect(request.referrer or url_for("entities"))


@app.route("/entities/<int:eid>/delete", methods=["POST"])
@login_required
@require_role(ROLE_TOP)
def entity_delete(eid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    ok, err = delete_entity_and_children(eid)
    if not ok:
        flash(f"Delete failed: {err}", "error")
    return redirect(url_for("entities"))


@app.route("/cases/<int:cid>/entities", methods=["POST"])
@login_required
def case_entity_add(cid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
        index_text("entity", e.id, f"{e.name}")
        link = CaseEntity(case_id=c.id, entity_id=e.id, role=role)
        link.case = c
        link.note = note
        db.session.add(link)
        db.session.commit()
        custody(cid, "EDIT", f"Person added: {name} as {role}")
        audit("case_entity_add", f"{name} ({role})", actor=current_user.username)
        flash("Person added.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/case-entities/<int:link_id>/edit", methods=["POST"])
@login_required
def case_entity_edit(link_id):
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
    link = db.session.get(CaseEntity, link_id) or abort(404)
    if not can_write_case_entries(current_user, link.case):
        abort(403)
    cid = link.case_id
    db.session.delete(link)
    db.session.commit()
    return redirect(url_for("case_detail", cid=cid))


# ============================================================
# RESOLUTION / GRAPH / DEEP SEARCH (Wave 1)
# ============================================================
def _similarity(name_a, name_b):
    a = name_a.lower().strip()
    b = name_b.lower().strip()
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    ta = set(re.findall(r"[a-z0-9]+", a))
    tb = set(re.findall(r"[a-z0-9]+", b))
    if not ta or not tb:
        return 0.0
    jaccard = len(ta & tb) / len(ta | tb)
    prefix = 0.0
    if a[0] == b[0]:
        prefix += 0.1
    if a[:4] == b[:4]:
        prefix += 0.15
    if a in b or b in a:
        prefix += 0.2
    return min(1.0, jaccard + prefix)


@app.route("/resolution")
@login_required
@require_role(ROLE_TOP, ROLE_ANALYST)
def resolution():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    rows = db.session.execute(
        db.select(Entity).where(Entity.merged_into_id == None).order_by(Entity.name)
    ).scalars().all()
    suggestions = []
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            a, b = rows[i], rows[j]
            if a.type != b.type:
                continue
            sim = _similarity(a.name, b.name)
            if a.region and b.region and a.region.lower() == b.region.lower():
                sim += 0.15
            if sim >= 0.5:
                suggestions.append({
                    "a": a, "b": b, "similarity": round(sim, 2),
                    "reason": _why_similar(a, b),
                })
    suggestions.sort(key=lambda s: s["similarity"], reverse=True)
    return render_template("resolution.html", suggestions=suggestions)


def _why_similar(a, b):
    reasons = []
    if a.name.lower() == b.name.lower():
        reasons.append("identical name")
    if a.region and b.region and a.region.lower() == b.region.lower():
        reasons.append(f"same region ({a.region})")
    if a.type == b.type:
        reasons.append(f"same type ({a.type})")
    ta = set(re.findall(r"[a-z]+", a.name.lower()))
    tb = set(re.findall(r"[a-z]+", b.name.lower()))
    common = ta & tb
    if common:
        reasons.append("shares name parts: " + ", ".join(sorted(common)))
    return " · ".join(reasons) or "similar spelling"


@app.route("/resolution/merge", methods=["POST"])
@login_required
@require_role(ROLE_TOP, ROLE_ANALYST)
def resolution_merge():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    keep_id = request.form.get("keep_id", type=int)
    merge_id = request.form.get("merge_id", type=int)
    if not keep_id or not merge_id or keep_id == merge_id:
        flash("Invalid merge.", "error")
        return redirect(url_for("resolution"))
    keep = db.session.get(Entity, keep_id)
    merge = db.session.get(Entity, merge_id)
    if not keep or not merge:
        flash("Entity not found.", "error")
        return redirect(url_for("resolution"))
    links = db.session.execute(
        db.select(CaseEntity).where(CaseEntity.entity_id == merge.id)
    ).scalars().all()
    for link in links:
        existing = db.session.execute(
            db.select(CaseEntity).where(
                CaseEntity.case_id == link.case_id,
                CaseEntity.entity_id == keep.id
            )
        ).scalar()
        if existing:
            if link.note and link.note not in (existing.note or ""):
                existing.note = ((existing.note or "") + "\n" + link.note).strip()
            db.session.delete(link)
        else:
            link.entity_id = keep.id
    rels = db.session.execute(
        db.select(Relationship).where(
            or_(Relationship.from_id == merge.id, Relationship.to_id == merge.id)
        )
    ).scalars().all()
    for r in rels:
        if r.from_id == merge.id:
            r.from_id = keep.id
        if r.to_id == merge.id:
            r.to_id = keep.id
        if r.from_id == r.to_id:
            db.session.delete(r)
    if merge.notes and merge.notes not in (keep.notes or ""):
        keep.notes = ((keep.notes or "") + "\n" + merge.notes).strip()
    merge.merged_into_id = keep.id
    index_text("entity", keep.id, f"{keep.name} {keep.notes} {keep.region}")
    db.session.commit()
    audit("entity_merge", f"{merge.name} → {keep.name}", actor=current_user.username)
    flash(f"Merged '{merge.name}' into '{keep.name}'.", "success")
    return redirect(url_for("resolution"))


@app.route("/resolution/unmerge/<int:eid>", methods=["POST"])
@login_required
@require_role(ROLE_TOP)
def resolution_unmerge(eid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    e = db.session.get(Entity, eid) or abort(404)
    e.merged_into_id = None
    db.session.commit()
    flash(f"'{e.name}' restored as standalone entity.", "success")
    return redirect(url_for("resolution"))


@app.route("/graph")
@login_required
def graph():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    entities = db.session.execute(
        db.select(Entity).where(Entity.merged_into_id == None)
    ).scalars().all()
    rels = db.session.execute(db.select(Relationship)).scalars().all()
    G = nx.Graph()
    entity_map = {e.id: e for e in entities}
    for e in entities:
        G.add_node(e.id)
    for r in rels:
        if r.from_id in entity_map and r.to_id in entity_map:
            if G.has_edge(r.from_id, r.to_id):
                G[r.from_id][r.to_id]["weight"] += 1
                G[r.from_id][r.to_id]["relations"].append(r.relation)
            else:
                G.add_edge(r.from_id, r.to_id, weight=1, relations=[r.relation])
    communities = {}
    if G.number_of_nodes() > 0:
        try:
            for i, c in enumerate(nx.algorithms.community.greedy_modularity_communities(G)):
                for node in c:
                    communities[node] = i
        except Exception:
            for node in G.nodes:
                communities[node] = 0
    try:
        centrality = nx.degree_centrality(G) if G.number_of_nodes() else {}
    except Exception:
        centrality = {}
    nodes = []
    for e in entities:
        nodes.append({
            "id": e.id, "name": e.name, "type": e.type,
            "threat": e.threat_level, "region": e.region,
            "community": communities.get(e.id, 0),
            "degree": G.degree(e.id) if e.id in G else 0,
            "centrality": round(centrality.get(e.id, 0), 3) if centrality else 0,
        })
    edges = []
    for u, v, data in G.edges(data=True):
        edges.append({
            "source": u, "target": v,
            "weight": data.get("weight", 1),
            "relations": data.get("relations", []),
        })
    top = sorted(nodes, key=lambda n: n["degree"], reverse=True)[:10]
    return render_template("graph.html", nodes=nodes, edges=edges, top=top,
                           num_nodes=len(nodes), num_edges=len(edges),
                           num_communities=len(set(communities.values())) if communities else 0)


@app.route("/graph/path")
@login_required
def graph_path():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    a = request.args.get("from", type=int)
    b = request.args.get("to", type=int)
    if not a or not b:
        flash("Choose two entities.", "error")
        return redirect(url_for("graph"))
    entities = db.session.execute(
        db.select(Entity).where(Entity.merged_into_id == None)
    ).scalars().all()
    rels = db.session.execute(db.select(Relationship)).scalars().all()
    G = nx.Graph()
    for e in entities:
        G.add_node(e.id)
    for r in rels:
        G.add_edge(r.from_id, r.to_id)
    try:
        path = nx.shortest_path(G, source=a, target=b)
        path_data = []
        for pid in path:
            e = db.session.get(Entity, pid)
            path_data.append({"id": pid, "name": e.name if e else "?"})
        return render_template("graph_path.html", path=path_data, a=a, b=b)
    except Exception:
        flash("No connection found.", "error")
        return redirect(url_for("graph"))


@app.route("/deep-search")
@login_required
def deep_search():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    q = (request.args.get("q") or "").strip()
    results = {"cases": [], "updates": [], "analyst_notes": [], "entities": [], "voice": []}
    if q:
        words = extract_keywords(q)
        if not words:
            return render_template("deep_search.html", q=q, results=results)
        hashes = [keyword_hash(w) for w in words]
        hits = db.session.execute(
            db.select(SearchIndex).where(SearchIndex.kw_hash.in_(hashes))
        ).scalars().all()
        buckets = {}
        for h in hits:
            key = (h.source_type, h.source_id)
            buckets[key] = buckets.get(key, 0) + 1
        min_words = 1 if len(words) == 1 else max(1, len(words) // 2)
        sorted_buckets = sorted(buckets.items(), key=lambda x: x[1], reverse=True)
        for (stype, sid), score in sorted_buckets:
            if score < min_words:
                continue
            if stype == "case":
                obj = db.session.get(Case, sid)
                if obj and can_view_case(current_user, obj):
                    results["cases"].append(obj)
            elif stype == "update":
                obj = db.session.get(Update, sid)
                if obj and obj.case and can_view_case(current_user, obj.case):
                    results["updates"].append(obj)
            elif stype == "analyst_note":
                obj = db.session.get(AnalystNote, sid)
                if obj and current_user.role in (ROLE_TOP, ROLE_ANALYST):
                    results["analyst_notes"].append(obj)
            elif stype == "entity":
                obj = db.session.get(Entity, sid)
                if obj:
                    results["entities"].append(obj)
            elif stype == "voice":
                obj = db.session.get(UpdateMedia, sid)
                if obj and obj.update and obj.update.case and can_view_case(current_user, obj.update.case):
                    results["voice"].append(obj)
    return render_template("deep_search.html", q=q, results=results)


@app.route("/deep-search/reindex", methods=["POST"])
@login_required
@require_role(ROLE_TOP)
def deep_search_reindex():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    SearchIndex.query.delete()
    for c in db.session.execute(db.select(Case)).scalars().all():
        index_text("case", c.id, f"{c.title} {c.subject} {c.notes}", case_id=c.id)
    for u in db.session.execute(db.select(Update)).scalars().all():
        index_text("update", u.id, u.body, case_id=u.case_id)
    for n in db.session.execute(db.select(AnalystNote)).scalars().all():
        index_text("analyst_note", n.id, f"{n.title} {n.body}", case_id=n.case_id)
    for e in db.session.execute(db.select(Entity)).scalars().all():
        index_text("entity", e.id, f"{e.name} {e.notes} {e.region}")
    for m in db.session.execute(db.select(UpdateMedia).where(UpdateMedia.kind == "voice")).scalars().all():
        if m.transcript:
            index_text("voice", m.id, m.transcript, case_id=m.update.case_id if m.update else None)
    db.session.commit()
    audit("search_reindex", "full rebuild", actor=current_user.username)
    flash("Search index rebuilt.", "success")
    return redirect(url_for("deep_search"))


# ============================================================
# PATTERNS / GEO (Wave 3)
# ============================================================
@app.route("/patterns")
@login_required
def patterns():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    if current_user.role not in (ROLE_TOP, ROLE_ANALYST):
        flash("Analyst or Top Secret only.", "error")
        return redirect(url_for("dashboard"))
    all_updates = db.session.execute(
        db.select(Update).order_by(Update.happened_at.asc())
    ).scalars().all()
    visible = [u for u in all_updates if can_view_case(current_user, u.case)]
    cooc = Counter()
    entities = db.session.execute(
        db.select(Entity).where(Entity.merged_into_id == None)
    ).scalars().all()
    name_to_id = {e.name.lower(): e.id for e in entities}
    entity_by_id = {e.id: e for e in entities}
    for u in visible:
        body_lower = (u.body or "").lower()
        hits = []
        for name, eid in name_to_id.items():
            if name in body_lower:
                hits.append(eid)
        for i in range(len(hits)):
            for j in range(i + 1, len(hits)):
                key = tuple(sorted((hits[i], hits[j])))
                cooc[key] += 1
    co_occurrences = []
    for (a, b), count in cooc.most_common(15):
        if count >= 2:
            co_occurrences.append({"a": entity_by_id.get(a), "b": entity_by_id.get(b), "count": count})
    weekday_counts = Counter()
    hour_counts = Counter()
    for u in visible:
        dt = u.happened_at
        weekday_counts[dt.strftime("%A")] += 1
        hour_counts[dt.hour] += 1
    weekday_order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    weekday_data = [(d, weekday_counts.get(d, 0)) for d in weekday_order]
    max_weekday = max([c for _, c in weekday_data]) or 1
    hour_data = [(h, hour_counts.get(h, 0)) for h in range(24)]
    max_hour = max([c for _, c in hour_data]) or 1
    lengths = [len(u.body or "") for u in visible if u.body]
    avg_len = sum(lengths) / len(lengths) if lengths else 0
    long_updates = [u for u in visible if u.body and len(u.body) > avg_len * 2.5 and len(u.body) > 300][:10]
    gaps = []
    sorted_updates = sorted(visible, key=lambda u: u.happened_at)
    for i in range(1, len(sorted_updates)):
        delta = sorted_updates[i].happened_at - sorted_updates[i-1].happened_at
        if delta.days >= 14:
            gaps.append({"from": sorted_updates[i-1].happened_at, "to": sorted_updates[i].happened_at, "days": delta.days})
    first_appearances = []
    for e in entities:
        name_lower = e.name.lower()
        for u in sorted_updates:
            if name_lower in (u.body or "").lower():
                first_appearances.append({"entity": e, "when": u.happened_at, "update": u})
                break
    first_appearances.sort(key=lambda x: x["when"], reverse=True)
    first_appearances = first_appearances[:10]
    same_region = []
    region_groups = defaultdict(list)
    for e in entities:
        if e.region:
            region_groups[e.region.lower()].append(e)
    for region, group in region_groups.items():
        if len(group) >= 2:
            same_region.append({"region": group[0].region, "entities": group})
    stats = {
        "total_updates": len(visible),
        "avg_length": int(avg_len),
        "unique_entities": len(entities),
        "co_occurrences": len(co_occurrences),
    }
    return render_template("patterns.html",
                           stats=stats,
                           co_occurrences=co_occurrences,
                           weekday_data=weekday_data,
                           max_weekday=max_weekday,
                           hour_data=hour_data,
                           max_hour=max_hour,
                           long_updates=long_updates,
                           gaps=gaps,
                           first_appearances=first_appearances,
                           same_region=same_region)


@app.route("/geo")
@login_required
def geo():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    entities = db.session.execute(
        db.select(Entity).where(Entity.merged_into_id == None)
    ).scalars().all()
    with_coords = [e for e in entities if e.latitude and e.longitude]
    region_groups = defaultdict(list)
    for e in entities:
        if e.region:
            region_groups[e.region.lower()].append(e)
    co_located = []
    for region, group in region_groups.items():
        if len(group) >= 2:
            co_located.append({"region": group[0].region, "entities": group})
    region_counts = Counter()
    for e in entities:
        if e.region:
            region_counts[e.region] += 1
    markers = [{
        "id": e.id, "name": e.name, "type": e.type,
        "lat": e.latitude, "lng": e.longitude,
        "threat": e.threat_level, "region": e.region,
        "color": {"LOW": "#3fb950", "MEDIUM": "#ffb000",
                  "HIGH": "#ff7b00", "CRITICAL": "#ff3b30"}.get(e.threat_level, "#8a8577"),
    } for e in with_coords]
    nearby_pairs = []
    for i in range(len(with_coords)):
        for j in range(i + 1, len(with_coords)):
            a, b = with_coords[i], with_coords[j]
            dlat = abs(a.latitude - b.latitude)
            dlng = abs(a.longitude - b.longitude)
            if dlat < 0.5 and dlng < 0.5:
                nearby_pairs.append({"a": a, "b": b, "dlat": dlat, "dlng": dlng})
    return render_template("geo.html",
                           markers=markers,
                           co_located=co_located,
                           nearby_pairs=nearby_pairs,
                           region_counts=region_counts.most_common(20),
                           total_located=len(markers))


# ============================================================
# RELATIONSHIPS / CONTACTS / SEARCH / ACTIVITY
# ============================================================
@app.route("/who-knows-who", methods=["GET", "POST"])
@login_required
def relationships():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
    r = db.session.get(Relationship, rid) or abort(404)
    db.session.delete(r)
    db.session.commit()
    return redirect(url_for("relationships"))


@app.route("/contacts", methods=["GET", "POST"])
@login_required
def contacts():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
    s = db.session.get(Source, sid) or abort(404)
    db.session.delete(s)
    db.session.commit()
    return redirect(url_for("contacts"))


@app.route("/search")
@login_required
def search():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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



# ============================================================
# TIMED NOTES / BRIEFING / MAP
# ============================================================
@app.route("/timed-notes", methods=["GET", "POST"])
@login_required
def drops():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
    d = db.session.get(DeadDrop, did) or abort(404)
    db.session.delete(d)
    db.session.commit()
    return redirect(url_for("drops"))


@app.route("/briefing")
@login_required
def briefing():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    days = int(request.args.get("days", 1))
    since = datetime.now() - timedelta(days=days)
    updates = db.session.execute(
        db.select(Update).where(Update.happened_at >= since).order_by(Update.happened_at.desc())
    ).scalars().all()
    updates = [u for u in updates if can_view_case(current_user, u.case)]
    return render_template("briefing.html", days=days, since=since, updates=updates)


@app.route("/map")
@login_required
def map_view():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
# WAVE 4 — DEAD MAN'S SWITCH ROUTES
# ============================================================
@app.route("/settings/deadman", methods=["GET", "POST"])
@login_required
def setup_deadman():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    form = DeadManForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "error")
        else:
            current_user.deadman_enabled = form.enabled.data
            current_user.deadman_days = max(1, form.days.data or 7)
            current_user.deadman_message = form.message.data or ""
            if form.enabled.data:
                current_user.deadman_last_checkin = datetime.utcnow()
                current_user.deadman_fired_at = None
            db.session.commit()
            audit("deadman_updated",
                  f"{'enabled' if form.enabled.data else 'disabled'} ({current_user.deadman_days}d)",
                  actor=current_user.username)
            flash("Dead Man's Switch saved.", "success")
            return redirect(url_for("dashboard"))
    else:
        form.enabled.data = current_user.deadman_enabled
        form.days.data = current_user.deadman_days or 7
        form.message.data = current_user.deadman_message or ""
    return render_template("setup_deadman.html", form=form,
                           configured=bool(app.config.get("TELEGRAM_BOT_TOKEN")),
                           status=current_user.deadman_status(),
                           last=current_user.deadman_last_checkin,
                           days_left=current_user.deadman_days_left(),
                           contact=app.config.get("TELEGRAM_CHAT_ID", ""))


@app.route("/settings/deadman/checkin", methods=["POST"])
@login_required
def deadman_checkin():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    current_user.deadman_last_checkin = datetime.utcnow()
    current_user.deadman_fired_at = None
    db.session.commit()
    audit("deadman_checkin", current_user.username, actor=current_user.username)
    flash("Checked in. Timer reset.", "success")
    return redirect(url_for("dashboard"))


@app.route("/settings/deadman/test", methods=["POST"])
@login_required
def deadman_test():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    ok = send_telegram_alert(
        f"🧪 Test alert from MIS.\n"
        f"If you receive this, your Dead Man's Switch is wired correctly.\n"
        f"User: {current_user.username}"
    )
    if ok:
        flash("Test alert sent to Telegram.", "success")
    else:
        flash("Telegram not configured, or send failed. Check env vars.", "error")
    return redirect(url_for("setup_deadman"))


# ============================================================
# WAVE 4 — STRUCTURED EXPORTS
# ============================================================
@app.route("/exports", methods=["GET", "POST"])
@login_required
def exports():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    form = ExportForm()
    form.case_id.choices = [(0, "— none —")] + case_choices_for(current_user)
    if form.validate_on_submit():
        # Determine cases
        if form.scope.data == "single" and form.case_id.data:
            c = db.session.get(Case, form.case_id.data)
            if not c or not can_view_case(current_user, c):
                abort(403)
            cases = [c]
        else:
            if current_user.role in (ROLE_TOP, ROLE_ANALYST):
                cases = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
            else:
                cases = db.session.execute(
                    db.select(Case).where(Case.assigned_agent_id == current_user.id)
                ).scalars().all()

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fmt = form.format.data

        if fmt == "json":
            data = export_json(cases, current_user)
            fname = f"MIS_export_{stamp}.json"
            mimetype = "application/json"
        elif fmt == "csv":
            data = export_csv_zip(cases, current_user)
            fname = f"MIS_export_{stamp}.zip"
            mimetype = "application/zip"
        elif fmt == "kml":
            data = export_kml(cases, current_user)
            fname = f"MIS_export_{stamp}.kml"
            mimetype = "application/vnd.google-earth.kml+xml"
        elif fmt == "stix":
            data = export_stix(cases, current_user)
            fname = f"MIS_export_{stamp}_stix.json"
            mimetype = "application/json"
        else:
            flash("Unknown format.", "error")
            return redirect(url_for("exports"))

        audit("export", f"{fmt} of {len(cases)} cases", actor=current_user.username)
        resp = send_file(io.BytesIO(data), mimetype=mimetype,
                         as_attachment=True, download_name=fname)
        resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
        resp.headers["Cache-Control"] = "no-store"
        return resp
    return render_template("exports.html", form=form)


# ============================================================
# BACKUPS (Top Secret only)
# ============================================================
@app.route("/backups")
@login_required
@require_role(ROLE_TOP)
def backups():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    rows = db.session.execute(db.select(Backup).order_by(Backup.created_at.desc())).scalars().all()
    return render_template("backups.html", backups=rows)


@app.route("/backups/create", methods=["POST"])
@login_required
@require_role(ROLE_TOP)
def backup_create():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
# USERS (Top Secret only)
# ============================================================
@app.route("/users", methods=["GET", "POST"])
@login_required
@require_role(ROLE_TOP)
def users():
    if is_duress_session():
        return redirect(url_for("duress_home"))
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
    if is_duress_session():
        return redirect(url_for("duress_home"))
    if uid == current_user.id:
        flash("Cannot delete yourself.", "error")
        return redirect(url_for("users"))
    u = db.session.get(User, uid) or abort(404)
    db.session.delete(u)
    db.session.commit()
    return redirect(url_for("users"))


# ============================================================
# WAVE 4 — API KEYS
# ============================================================
@app.route("/settings/api-keys", methods=["GET", "POST"])
@login_required
@require_role(ROLE_TOP)
def api_keys():
    if is_duress_session():
        return redirect(url_for("duress_home"))
    new_key = None
    if request.method == "POST":
        label = (request.form.get("label") or "").strip()
        role = request.form.get("role") or ROLE_ANALYST
        if role not in (ROLE_TOP, ROLE_AGENT, ROLE_ANALYST):
            role = ROLE_ANALYST
        raw = "mis_" + secrets.token_urlsafe(24)
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        db.session.add(APIKey(key_hash=key_hash, label=label, role=role,
                              created_by=current_user.username))
        db.session.commit()
        audit("api_key_create", f"{label} ({role})", actor=current_user.username)
        new_key = raw
        flash("API key created. Copy it now — it won't be shown again.", "success")
    rows = db.session.execute(
        db.select(APIKey).where(APIKey.revoked == False).order_by(APIKey.created_at.desc())
    ).scalars().all()
    return render_template("api_keys.html", keys=rows, new_key=new_key)


@app.route("/settings/api-keys/<int:kid>/revoke", methods=["POST"])
@login_required
@require_role(ROLE_TOP)
def api_key_revoke(kid):
    if is_duress_session():
        return redirect(url_for("duress_home"))
    k = db.session.get(APIKey, kid) or abort(404)
    k.revoked = True
    db.session.commit()
    flash("API key revoked.", "success")
    return redirect(url_for("api_keys"))


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


@app.route("/offline")
def offline():
    return render_template("offline.html")


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
        for c in db.session.execute(db.select(Case)).scalars().all():
            if not c.case_key_wrapped:
                c.case_key_wrapped = wrap_case_key(new_case_key())
                c.key_rotated_at = datetime.utcnow()
        db.session.commit()
        print("✅ Case keys ensured")
        print(f"✅ Telegram configured: {bool(app.config.get('TELEGRAM_BOT_TOKEN'))}")


bootstrap()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
