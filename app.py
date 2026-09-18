# ============================================================
# MIS v10 — Full app with cache-busting service worker headers
# ============================================================

import os
import io
import hashlib
import secrets
from datetime import datetime, timedelta

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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib import colors

from pypdf import PdfReader, PdfWriter

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


app = Flask(__name__)
app.config.from_object(Config)

from flask_wtf.csrf import generate_csrf

@app.context_processor
def _inject_csrf():
    return {"csrf_token": generate_csrf}

@app.context_processor
def _inject_now():
    return {"now": datetime.utcnow()}

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
    last_login = db.Column(db.DateTime, nullable=True)
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
    links = db.relationship("CaseEntity", backref="case", lazy=True,
                            cascade="all, delete-orphan")


class Update(db.Model):
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
    notes = db.Column(db.Text, default="")
    verified = db.Column(db.Boolean, default=False)
    threat_level = db.Column(db.String(20), default="LOW")
    region = db.Column(db.String(120), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CaseEntity(db.Model):
    __tablename__ = "mis_case_entities"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("mis_cases.id"), nullable=False)
    entity_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    role = db.Column(db.String(80), default="Other")
    note = db.Column(db.Text, default="")
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    entity = db.relationship("Entity")


class Relationship(db.Model):
    __tablename__ = "mis_relationships"
    id = db.Column(db.Integer, primary_key=True)
    from_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    to_id = db.Column(db.Integer, db.ForeignKey("mis_entities.id"), nullable=False)
    relation = db.Column(db.String(80), default="knows")
    description = db.Column(db.Text, default="")
    case_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    from_entity = db.relationship("Entity", foreign_keys=[from_id], backref="outgoing")
    to_entity = db.relationship("Entity", foreign_keys=[to_id], backref="incoming")


class Source(db.Model):
    __tablename__ = "mis_sources"
    id = db.Column(db.Integer, primary_key=True)
    handle = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    case_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class DeadDrop(db.Model):
    __tablename__ = "mis_dead_drops"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, default="")
    unlock_at = db.Column(db.DateTime, nullable=False)
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
        ("last_login", "TIMESTAMP"),
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
    ],
    "mis_relationships": [
        ("description", "TEXT DEFAULT ''"),
        ("case_id", "INTEGER"),
    ],
    "mis_sources": [
        ("description", "TEXT DEFAULT ''"),
        ("case_id", "INTEGER"),
    ],
    "mis_dead_drops": [
        ("created_by", "VARCHAR(80) DEFAULT 'system'"),
    ],
    "mis_case_entities": [
        ("role", "VARCHAR(80) DEFAULT 'Other'"),
        ("note", "TEXT DEFAULT ''"),
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
# BULLETPROOF DELETE HELPERS
# ============================================================
def delete_case_and_children(cid):
    try:
        with db.engine.begin() as conn:
            conn.execute(text("""
                DELETE FROM mis_update_media
                WHERE update_id IN (SELECT id FROM mis_updates WHERE case_id = :cid)
            """), {"cid": cid})
            rows = conn.execute(text("""
                SELECT table_name FROM information_schema.columns
                WHERE column_name = 'case_id'
                  AND table_schema = current_schema()
                  AND table_name LIKE 'mis_%'
                  AND table_name <> 'mis_cases'
            """)).fetchall()
            for (tbl,) in rows:
                try:
                    conn.execute(text(f"DELETE FROM {tbl} WHERE case_id = :cid"), {"cid": cid})
                except Exception as e:
                    print(f"⚠️  Skipped {tbl}: {e}")
            conn.execute(text("DELETE FROM mis_cases WHERE id = :cid"), {"cid": cid})
        return True, None
    except Exception as e:
        return False, str(e)


def delete_entity_and_children(eid):
    try:
        with db.engine.begin() as conn:
            rows = conn.execute(text("""
                SELECT table_name, column_name
                FROM information_schema.columns
                WHERE column_name IN ('entity_id', 'from_id', 'to_id')
                  AND table_schema = current_schema()
                  AND table_name LIKE 'mis_%'
                  AND table_name <> 'mis_entities'
            """)).fetchall()
            for tbl, col in rows:
                try:
                    conn.execute(text(f"DELETE FROM {tbl} WHERE {col} = :eid"), {"eid": eid})
                except Exception as e:
                    print(f"⚠️  Skipped {tbl}.{col}: {e}")
            conn.execute(text("DELETE FROM mis_entities WHERE id = :eid"), {"eid": eid})
        return True, None
    except Exception as e:
        return False, str(e)


def delete_update_and_children(uid):
    try:
        with db.engine.begin() as conn:
            rows = conn.execute(text("""
                SELECT table_name FROM information_schema.columns
                WHERE column_name = 'update_id'
                  AND table_schema = current_schema()
                  AND table_name LIKE 'mis_%'
                  AND table_name <> 'mis_updates'
            """)).fetchall()
            for (tbl,) in rows:
                try:
                    conn.execute(text(f"DELETE FROM {tbl} WHERE update_id = :uid"), {"uid": uid})
                except Exception as e:
                    print(f"⚠️  Skipped {tbl}: {e}")
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
    submit = SubmitField("Authenticate")


class ChangePasswordForm(FlaskForm):
    current = PasswordField("Current Password", validators=[DataRequired()])
    new = PasswordField("New Password", validators=[DataRequired(), Length(min=10)])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("new")])
    submit = SubmitField("Update Password")


class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    codename = StringField("Display name", validators=[Optional(), Length(0, 80)])
    clearance = SelectField("Clearance", choices=[
        ("CONFIDENTIAL", "Confidential"),
        ("SECRET", "Secret"),
        ("TOP_SECRET", "Top Secret"),
        ("EYES_ONLY", "Eyes Only"),
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
    happened_at = DateTimeField("When", format="%Y-%m-%d %H:%M", validators=[Optional()])
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
    submit = SubmitField("Download PDF")


# ============================================================
# HELPERS
# ============================================================
def case_choices():
    rows = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    return [(c.id, c.title) for c in rows]


def entity_choices():
    rows = db.session.execute(db.select(Entity).order_by(Entity.name)).scalars().all()
    return [(e.id, f"{e.name} ({e.type})") for e in rows]


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def esc(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ============================================================
# PDF BUILDER
# ============================================================
def build_case_pdf(case: Case) -> bytes:
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
    story.append(Paragraph("MIS CASE FILE", h1))
    story.append(Paragraph(esc(case.title), h2))
    if case.subject:
        story.append(Paragraph(f"Subject: {esc(case.subject)}", body))
    story.append(Paragraph(
        f"Status: {esc(case.status)} · Threat: {esc(case.threat_level)} · Priority: {case.priority}",
        body))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", meta))
    story.append(Spacer(1, 0.4 * cm))

    if case.notes:
        story.append(Paragraph("Case Notes", h2))
        for para in (case.notes or "").split("\n"):
            if para.strip():
                story.append(Paragraph(esc(para), body))
        story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Chronological Record", h2))
    updates = sorted(case.updates, key=lambda u: u.happened_at, reverse=False)
    if updates:
        for u in updates:
            story.append(Paragraph(u.happened_at.strftime("%d %b %Y · %H:%M"), h3))
            if u.body:
                for para in (u.body or "").split("\n"):
                    if para.strip():
                        story.append(Paragraph(esc(para), body))

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
                        story.append(Spacer(1, 0.15 * cm))
                    except Exception as e:
                        story.append(Paragraph(
                            f"[Image could not embed: {esc(m.filename)} — {esc(str(e))}]",
                            meta))

            for m in u.photos:
                if m.kind == "voice":
                    story.append(Paragraph(
                        f"[Voice memo attached: {esc(m.filename or 'audio')}] "
                        f"— extract the attachment from this PDF to play.", meta))

            story.append(Spacer(1, 0.25 * cm))
    else:
        story.append(Paragraph("— no entries —", body))
    story.append(Spacer(1, 0.3 * cm))

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

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        "Handling: This file documents observations and information for lawful purposes. "
        "If information indicates imminent risk, contact authorities.", meta))

    doc.build(story)
    return buf.getvalue()


def encrypt_pdf_with_attachments(pdf_bytes: bytes, password: str,
                                  attachments: list) -> bytes:
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    for att in attachments:
        try:
            writer.add_attachment(
                filename=att["name"],
                data=att["data"],
            )
        except Exception as e:
            print(f"⚠️  Could not attach {att.get('name')}: {e}")

    writer.encrypt(
        user_password=password,
        owner_password=password,
        permissions_flag=-1,
        algorithm="AES-256",
    )

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
        if user and user.check_password(form.password.data):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            audit("login_success", f"{user.username} logged in", actor=user.username)
            return redirect(url_for("dashboard"))
        flash("Access denied. Check credentials.", "error")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    audit("logout", current_user.username, actor=current_user.username)
    logout_user()
    flash("Session terminated.", "success")
    return redirect(url_for("login"))


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


# ============================================================
# ROUTES — HOME
# ============================================================
@app.route("/dashboard")
@login_required
def dashboard():
    cases = db.session.execute(db.select(Case).order_by(Case.title)).scalars().all()
    recent = db.session.execute(
        db.select(Update).order_by(Update.happened_at.desc()).limit(20)
    ).scalars().all()
    stats = {
        "cases": db.session.scalar(db.select(db.func.count(Case.id))) or 0,
        "updates": db.session.scalar(db.select(db.func.count(Update.id))) or 0,
        "media": db.session.scalar(db.select(db.func.count(UpdateMedia.id))) or 0,
        "entities": db.session.scalar(db.select(db.func.count(Entity.id))) or 0,
        "users": db.session.scalar(db.select(db.func.count(User.id))) or 0,
    }
    return render_template("dashboard.html", cases=cases, recent=recent,
                           case_choices=case_choices(), stats=stats)


# ============================================================
# ROUTES — QUICK ADD
# ============================================================
@app.route("/add", methods=["POST"])
@login_required
def quick_add():
    form = QuickAddForm()
    form.case_id.choices = case_choices()
    if not form.case_id.data or form.case_id.data == 0:
        flash("Select a case.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    body = (form.body.data or "").strip()
    when = form.happened_at.data or datetime.utcnow()

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

    u = Update(case_id=form.case_id.data, body=body, happened_at=when,
               created_by=current_user.username)
    db.session.add(u)
    db.session.flush()

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
            notes=form.notes.data or "",
            status=form.status.data,
            priority=form.priority.data or 3,
            threat_level=form.threat_level.data,
            due_date=form.due_date.data,
        )
        db.session.add(c)
        db.session.commit()
        audit("case_create", c.title, actor=current_user.username)
        flash("Case opened.", "success")
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
        c.threat_level = form.threat_level.data
        c.due_date = form.due_date.data
        db.session.commit()
        flash("Case updated.", "success")
        return redirect(url_for("case_detail", cid=c.id))

    return render_template(
        "case_detail.html",
        case=c, form=form,
        case_choices=case_choices(),
    )


@app.route("/cases/<int:cid>/delete", methods=["POST"])
@login_required
def case_delete(cid):
    c = db.session.get(Case, cid) or abort(404)
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
    form = ReportForm()
    if not form.validate_on_submit():
        flash("Password required (min 6 chars).", "error")
        return redirect(url_for("case_detail", cid=cid))

    pdf_bytes = build_case_pdf(c)

    attachments = []
    for u in c.updates:
        for m in u.photos:
            if m.kind == "voice" or (m.kind != "photo" and m.data):
                attachments.append({
                    "name": m.filename or f"memo_{m.id}.bin",
                    "data": m.data,
                    "mime": m.mimetype or "application/octet-stream",
                })

    try:
        encrypted_pdf = encrypt_pdf_with_attachments(
            pdf_bytes, form.password.data, attachments
        )
    except Exception as e:
        flash(f"Encryption failed: {e}", "error")
        return redirect(url_for("case_detail", cid=cid))

    audit("report_download",
          f"Case #{cid} — AES-256 PDF ({len(attachments)} attachments)",
          actor=current_user.username)

    safe_title = "".join(ch for ch in c.title if ch.isalnum() or ch in "-_")[:40] or "case"
    fname = f"MIS_{safe_title}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"

    resp = send_file(
        io.BytesIO(encrypted_pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=fname,
    )
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
    form = QuickAddForm(obj=u)
    form.case_id.choices = case_choices()
    form.case_id.data = u.case_id
    if form.validate_on_submit():
        u.body = (form.body.data or "").strip() or u.body
        u.happened_at = form.happened_at.data or u.happened_at
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
        flash("Entry updated.", "success")
        return redirect(url_for("case_detail", cid=u.case_id))
    return render_template("update_edit.html", form=form, update=u)


@app.route("/updates/<int:uid>/delete", methods=["POST"])
@login_required
def update_delete(uid):
    u = db.session.get(Update, uid) or abort(404)
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
    cid = m.update.case_id
    db.session.delete(m)
    db.session.commit()
    return redirect(url_for("case_detail", cid=cid))


@app.route("/media/<int:mid>/view")
@login_required
def media_view(mid):
    m = db.session.get(UpdateMedia, mid) or abort(404)
    mt = m.mimetype or "application/octet-stream"
    if m.kind == "photo" and not mt.startswith("image/"):
        mt = "image/jpeg"
    elif m.kind == "voice" and not mt.startswith("audio/"):
        mt = "audio/webm"
    return send_file(io.BytesIO(m.data), mimetype=mt,
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
def entity_delete(eid):
    ok, err = delete_entity_and_children(eid)
    if not ok:
        flash(f"Delete failed: {err}", "error")
        return redirect(url_for("entities"))
    return redirect(url_for("entities"))


@app.route("/cases/<int:cid>/entities", methods=["POST"])
@login_required
def case_entity_add(cid):
    c = db.session.get(Case, cid) or abort(404)
    name = (request.form.get("name") or "").strip()
    role = (request.form.get("role") or "Other").strip()
    note = (request.form.get("note") or "").strip()
    if name:
        e = Entity(name=name, type="Person")
        db.session.add(e)
        db.session.flush()
        db.session.add(CaseEntity(
            case_id=c.id, entity_id=e.id, role=role, note=note
        ))
        db.session.commit()
        audit("case_entity_add", f"{name} ({role})", actor=current_user.username)
        flash("Person added to case.", "success")
    return redirect(url_for("case_detail", cid=cid))


@app.route("/case-entities/<int:link_id>/edit", methods=["POST"])
@login_required
def case_entity_edit(link_id):
    link = db.session.get(CaseEntity, link_id) or abort(404)
    role = (request.form.get("role") or link.role or "Other").strip()
    note = (request.form.get("note") or "").strip()
    link.role = role
    link.note = note
    db.session.commit()
    flash("Person entry updated.", "success")
    return redirect(url_for("case_detail", cid=link.case_id))


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
                description=form.description.data or "",
            )
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
        s = Source(handle=form.handle.data, description=form.description.data or "")
        db.session.add(s)
        db.session.commit()
        flash("Contact saved.", "success")
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
        flash("Message sealed.", "success")
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
    since = datetime.utcnow() - timedelta(days=days)
    updates = db.session.execute(
        db.select(Update).where(Update.happened_at >= since)
        .order_by(Update.happened_at.asc())
    ).scalars().all()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2.0 * cm, rightMargin=2.0 * cm,
                            topMargin=2.0 * cm, bottomMargin=2.0 * cm,
                            title=f"MIS Briefing — {days}d")
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

    story = [Paragraph("MIS BRIEFING", h1),
             Paragraph(f"Last {days} day(s)", h2),
             Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", body),
             Spacer(1, 0.4 * cm)]

    if not updates:
        story.append(Paragraph("— no entries in this window —", body))
    for u in updates:
        c = db.session.get(Case, u.case_id)
        story.append(Paragraph(
            f"<b>{u.happened_at.strftime('%d %b %Y · %H:%M')}</b> — {esc(c.title) if c else '—'}",
            h3))
        if u.body:
            for para in (u.body or "").split("\n"):
                if para.strip():
                    story.append(Paragraph(esc(para), body))
        for m in u.photos:
            if m.kind == "photo":
                try:
                    img = Image(io.BytesIO(m.data))
                    iw, ih = img.imageWidth, img.imageHeight
                    ratio = min((15 * cm) / iw, (10 * cm) / ih, 1.0)
                    img.drawWidth = iw * ratio
                    img.drawHeight = ih * ratio
                    story.append(Spacer(1, 0.1 * cm))
                    story.append(img)
                except Exception:
                    story.append(Paragraph(f"[Image: {esc(m.filename)}]", body))
            elif m.kind == "voice":
                story.append(Paragraph(f"[Voice memo: {esc(m.filename or 'audio')}]", body))
        story.append(Spacer(1, 0.2 * cm))

    doc.build(story)
    pdf_bytes = buf.getvalue()

    attachments = []
    for u in updates:
        for m in u.photos:
            if m.kind == "voice":
                attachments.append({
                    "name": m.filename or f"memo_{m.id}.bin",
                    "data": m.data,
                    "mime": m.mimetype or "application/octet-stream",
                })

    encrypted_pdf = encrypt_pdf_with_attachments(
        pdf_bytes, form.password.data, attachments
    )

    audit("briefing_download", f"{days}d — AES-256 PDF", actor=current_user.username)

    fname = f"MIS_Briefing_{days}d_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"
    resp = send_file(
        io.BytesIO(encrypted_pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=fname,
    )
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


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
            flash("Username taken.", "error")
        else:
            u = User(username=uname, codename=form.codename.data or "",
                     clearance=form.clearance.data)
            u.set_password(form.password.data)
            db.session.add(u)
            db.session.commit()
            flash("User created.", "success")
            return redirect(url_for("users"))
    rows = db.session.execute(db.select(User).order_by(User.created_at)).scalars().all()
    return render_template("users.html", form=form, users=rows)


@app.route("/users/<int:uid>/delete", methods=["POST"])
@login_required
def user_delete(uid):
    if uid == current_user.id:
        flash("Cannot delete yourself.", "error")
        return redirect(url_for("users"))
    u = db.session.get(User, uid) or abort(404)
    db.session.delete(u)
    db.session.commit()
    return redirect(url_for("users"))


# ============================================================
# PWA — cache-busting headers
# ============================================================
@app.route("/manifest.json")
def manifest():
    resp = send_file(os.path.join(BASE_DIR, "static", "manifest.json"),
                     mimetype="application/manifest+json")
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
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
            print(f"✅ User {u} OK")


bootstrap()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
