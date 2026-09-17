# ============================================================
# MIS — Mugisha's Intelligence System
# Single-file Flask application: models + forms + routes + PDF
# ============================================================

import os
import io
import base64
import hashlib
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, send_file, abort, jsonify
)
from flask_login import (
    login_user, logout_user, login_required, current_user
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import (
    StringField, PasswordField, TextAreaField, SelectField,
    BooleanField, SubmitField, IntegerField
)
from wtforms.validators import DataRequired, Length, EqualTo, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# ---- PDF + crypto ----
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
    _db = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'mis.db')}")
    if _db.startswith("postgres://"):
        _db = _db.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _db
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }
    WTF_CSRF_TIME_LIMIT = None
    MAX_CONTENT_LENGTH = 40 * 1024 * 1024  # 40 MB upload cap
    INITIAL_USERNAME = os.getenv("INITIAL_USERNAME", "Mpc")
    INITIAL_PASSWORD = os.getenv("INITIAL_PASSWORD", "08800Mpc!")


# ============================================================
# EXTENSIONS
# ============================================================
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)

from flask_login import LoginManager
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in."


# ============================================================
# MODELS
# ============================================================
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw, method="pbkdf2:sha256", salt_length=16)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    @property
    def is_authenticated(self): return True
    @property
    def is_active(self): return True
    @property
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)


class Case(db.Model):
    __tablename__ = "cases"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    objective = db.Column(db.Text, default="")
    status = db.Column(db.String(40), default="Active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    notes = db.relationship("Note", backref="case", lazy=True, cascade="all, delete-orphan")
    evidence = db.relationship("Evidence", backref="case", lazy=True, cascade="all, delete-orphan")


class Person(db.Model):
    __tablename__ = "people"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(60), default="Person")
    notes = db.Column(db.Text, default="")
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, default="")
    source = db.Column(db.String(200), default="")
    reliability = db.Column(db.String(20), default="Unknown")
    confidence = db.Column(db.String(20), default="Unknown")
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Evidence(db.Model):
    __tablename__ = "evidence"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(255))
    mimetype = db.Column(db.String(120), default="application/octet-stream")
    data = db.Column(db.LargeBinary)          # stored in DB → survives restarts
    sha256 = db.Column(db.String(64), index=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    __tablename__ = "audit_log"
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
    username = StringField("Username", validators=[DataRequired(), Length(1, 80)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Access")


class ChangePasswordForm(FlaskForm):
    current = PasswordField("Current Password", validators=[DataRequired()])
    new = PasswordField("New Password", validators=[DataRequired(), Length(min=10)])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("new")])
    submit = SubmitField("Update Password")


class CaseForm(FlaskForm):
    title = StringField("Case Title", validators=[DataRequired(), Length(1, 200)])
    objective = TextAreaField("Objective")
    status = SelectField("Status", choices=[("Active","Active"),("Review","Review"),("Closed","Closed"),("Archived","Archived")])
    submit = SubmitField("Save")


class PersonForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(1, 200)])
    type = SelectField("Type", choices=[
        ("Person","Person"),("Organization","Organization"),("Company","Company"),
        ("Location","Location"),("Event","Event"),("Project","Project"),("Website","Website")
    ])
    notes = TextAreaField("Notes")
    verified = BooleanField("Verified")
    submit = SubmitField("Save")


class NoteForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    body = TextAreaField("Body")
    source = StringField("Source", validators=[Optional(), Length(0, 200)])
    reliability = SelectField("Source Reliability", choices=[("Unknown","Unknown"),("High","High"),("Medium","Medium"),("Low","Low")])
    confidence = SelectField("Information Confidence", choices=[("Unknown","Unknown"),("High","High"),("Medium","Medium"),("Low","Low")])
    case_id = SelectField("Related Case", coerce=int, validators=[Optional()])
    submit = SubmitField("Save Note")


class EvidenceForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    file = FileField("File", validators=[FileRequired()])
    case_id = SelectField("Related Case", coerce=int, validators=[Optional()])
    submit = SubmitField("Upload")


class ReportForm(FlaskForm):
    password = PasswordField("Encryption Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Download Encrypted PDF")


# ============================================================
# HELPERS
# ============================================================
def case_choices():
    rows = db.session.execute(db.select(Case).order_by(Case.id)).scalars().all()
    return [(0, "— none —")] + [(c.id, f"#{c.id} {c.title}") for c in rows]


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ============================================================
# PDF BUILDER
# ============================================================
def build_case_pdf(case: Case) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm,
        title=f"MIS Report — Case #{case.id}"
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], textColor=colors.HexColor("#1f3a8a"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#1f3a8a"))
    body = styles["BodyText"]

    story = []
    story.append(Paragraph("MIS INTELLIGENCE REPORT", h1))
    story.append(Paragraph("Mugisha's Intelligence System", styles["Italic"]))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(f"Case #{case.id} — {case.title}", h2))
    story.append(Paragraph(f"Status: {case.status}", body))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", body))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("1. Objective", h2))
    story.append(Paragraph(case.objective or "—", body))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("2. Notes", h2))
    if case.notes:
        for n in case.notes:
            story.append(Paragraph(
                f"<b>{n.title}</b> · {n.created_at.strftime('%Y-%m-%d')} · "
                f"Source: {n.source or '—'} · Rel: {n.reliability} · Conf: {n.confidence}",
                body
            ))
            story.append(Paragraph((n.body or "").replace("\n", "<br/>"), body))
            story.append(Spacer(1, 0.2*cm))
    else:
        story.append(Paragraph("— none —", body))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("3. Evidence Register", h2))
    if case.evidence:
        data = [["ID", "Title", "SHA-256 (trunc)", "Verified"]]
        for e in case.evidence:
            data.append([
                str(e.id), e.title or "",
                (e.sha256 or "")[:20] + "…",
                "YES" if e.verified else "NO"
            ])
        t = Table(data, colWidths=[1.2*cm, 7*cm, 6*cm, 2*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1f3a8a")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
            ("FONTSIZE", (0,0), (-1,-1), 8),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("— none —", body))

    story.append(PageBreak())
    story.append(Paragraph("4. Audit Footer", h2))
    story.append(Paragraph(
        "This document is encrypted with AES-256-GCM. "
        "Decrypt using Mpcipher Tool with the same password used at download.",
        body
    ))

    doc.build(story)
    return buf.getvalue()


# ============================================================
# MPC ENCRYPTION (compatible with Mpcipher Tool)
# Format: b"MIS1" + salt(16) + nonce(12) + ciphertext+tag
# ============================================================
MPC_MAGIC = b"MIS1"
PBKDF2_ITERATIONS = 200_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
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
        user = db.session.execute(db.select(User).filter_by(username=form.username.data)).scalar()
        if user and user.check_password(form.password.data):
            login_user(user)
            audit("login_success", f"{user.username} logged in", actor=user.username)
            return redirect(url_for("dashboard"))
        audit("login_fail", f"Attempt for {form.username.data}")
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
            audit("password_change_fail", current_user.username, actor=current_user.username)
            flash("Current password incorrect.", "error")
        else:
            current_user.set_password(form.new.data)
            db.session.commit()
            audit("password_change", current_user.username, actor=current_user.username)
            flash("Password updated.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html", form=form)


# ============================================================
# ROUTES — DASHBOARD
# ============================================================
@app.route("/dashboard")
@login_required
def dashboard():
    stats = {
        "cases": db.session.scalar(db.select(db.func.count(Case.id))) or 0,
        "people": db.session.scalar(db.select(db.func.count(Person.id))) or 0,
        "notes": db.session.scalar(db.select(db.func.count(Note.id))) or 0,
        "evidence": db.session.scalar(db.select(db.func.count(Evidence.id))) or 0,
    }
    recent = db.session.execute(
        db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(12)
    ).scalars().all()
    return render_template("dashboard.html", stats=stats, recent=recent)


# ============================================================
# ROUTES — CASES
# ============================================================
@app.route("/cases", methods=["GET", "POST"])
@login_required
def cases():
    form = CaseForm()
    if form.validate_on_submit():
        c = Case(title=form.title.data, objective=form.objective.data or "", status=form.status.data)
        db.session.add(c)
        db.session.commit()
        audit("case_create", f"#{c.id} {c.title}", actor=current_user.username)
        flash("Case created.", "success")
        return redirect(url_for("cases"))
    rows = db.session.execute(db.select(Case).order_by(Case.created_at.desc())).scalars().all()
    return render_template("cases.html", form=form, cases=rows)


@app.route("/cases/<int:cid>", methods=["GET", "POST"])
@login_required
def case_detail(cid):
    c = db.session.get(Case, cid) or abort(404)
    form = CaseForm(obj=c)
    if form.validate_on_submit():
        c.title = form.title.data
        c.objective = form.objective.data or ""
        c.status = form.status.data
        db.session.commit()
        audit("case_update", f"#{c.id}", actor=current_user.username)
        flash("Case updated.", "success")
        return redirect(url_for("case_detail", cid=c.id))
    report_form = ReportForm()
    return render_template("case_detail.html", case=c, form=form, report_form=report_form)


@app.route("/cases/<int:cid>/delete", methods=["POST"])
@login_required
def case_delete(cid):
    c = db.session.get(Case, cid) or abort(404)
    db.session.delete(c)
    db.session.commit()
    audit("case_delete", f"#{cid}", actor=current_user.username)
    flash("Case deleted.", "success")
    return redirect(url_for("cases"))


# ============================================================
# ROUTES — ENCRYPTED PDF DOWNLOAD
# ============================================================
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

    audit("report_download", f"Case #{cid} encrypted report", actor=current_user.username)

    fname = f"MIS_Case_{cid}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.mpcenc"
    return send_file(
        io.BytesIO(encrypted),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=fname
    )


# ============================================================
# ROUTES — PEOPLE
# ============================================================
@app.route("/people", methods=["GET", "POST"])
@login_required
def people():
    form = PersonForm()
    if form.validate_on_submit():
        p = Person(name=form.name.data, type=form.type.data,
                   notes=form.notes.data or "", verified=form.verified.data)
        db.session.add(p)
        db.session.commit()
        audit("person_create", p.name, actor=current_user.username)
        flash("Entity added.", "success")
        return redirect(url_for("people"))
    rows = db.session.execute(db.select(Person).order_by(Person.name)).scalars().all()
    return render_template("people.html", form=form, people=rows)


@app.route("/people/<int:pid>/delete", methods=["POST"])
@login_required
def person_delete(pid):
    p = db.session.get(Person, pid) or abort(404)
    db.session.delete(p)
    db.session.commit()
    audit("person_delete", p.name, actor=current_user.username)
    return redirect(url_for("people"))


# ============================================================
# ROUTES — NOTES
# ============================================================
@app.route("/notes", methods=["GET", "POST"])
@login_required
def notes():
    form = NoteForm()
    form.case_id.choices = case_choices()
    if form.validate_on_submit():
        n = Note(
            title=form.title.data, body=form.body.data or "",
            source=form.source.data or "",
            reliability=form.reliability.data, confidence=form.confidence.data,
            case_id=form.case_id.data or None,
        )
        db.session.add(n)
        db.session.commit()
        audit("note_create", n.title, actor=current_user.username)
        flash("Note saved.", "success")
        return redirect(url_for("notes"))
    rows = db.session.execute(db.select(Note).order_by(Note.created_at.desc())).scalars().all()
    return render_template("notes.html", form=form, notes=rows)


@app.route("/notes/<int:nid>/delete", methods=["POST"])
@login_required
def note_delete(nid):
    n = db.session.get(Note, nid) or abort(404)
    db.session.delete(n)
    db.session.commit()
    audit("note_delete", n.title, actor=current_user.username)
    return redirect(url_for("notes"))


# ============================================================
# ROUTES — EVIDENCE
# ============================================================
@app.route("/evidence", methods=["GET", "POST"])
@login_required
def evidence():
    form = EvidenceForm()
    form.case_id.choices = case_choices()
    if form.validate_on_submit():
        f = form.file.data
        raw = f.read()
        digest = sha256_bytes(raw)
        e = Evidence(
            title=form.title.data,
            filename=secure_filename(f.filename),
            mimetype=f.mimetype or "application/octet-stream",
            data=raw,
            sha256=digest,
            case_id=form.case_id.data or None,
        )
        db.session.add(e)
        db.session.commit()
        audit("evidence_add", f"{e.title} sha256={digest[:16]}…", actor=current_user.username)
        flash("Evidence stored & hashed.", "success")
        return redirect(url_for("evidence"))
    rows = db.session.execute(db.select(Evidence).order_by(Evidence.created_at.desc())).scalars().all()
    return render_template("evidence.html", form=form, evidence=rows)


@app.route("/evidence/<int:eid>/verify", methods=["POST"])
@login_required
def evidence_verify(eid):
    e = db.session.get(Evidence, eid) or abort(404)
    e.verified = True
    db.session.commit()
    audit("evidence_verify", f"#{eid}", actor=current_user.username)
    return redirect(url_for("evidence"))


@app.route("/evidence/<int:eid>/download")
@login_required
def evidence_download(eid):
    e = db.session.get(Evidence, eid) or abort(404)
    return send_file(
        io.BytesIO(e.data),
        mimetype=e.mimetype or "application/octet-stream",
        as_attachment=True,
        download_name=e.filename or f"evidence_{eid}.bin"
    )


# ============================================================
# ROUTES — SEARCH + AUDIT
# ============================================================
@app.route("/search")
@login_required
def search():
    q = (request.args.get("q") or "").strip()
    results = {"notes": [], "people": [], "cases": [], "evidence": []}
    if q:
        like = f"%{q}%"
        results["notes"] = db.session.execute(
            db.select(Note).where((Note.title.ilike(like)) | (Note.body.ilike(like)) | (Note.source.ilike(like)))
        ).scalars().all()
        results["people"] = db.session.execute(
            db.select(Person).where((Person.name.ilike(like)) | (Person.notes.ilike(like)))
        ).scalars().all()
        results["cases"] = db.session.execute(
            db.select(Case).where((Case.title.ilike(like)) | (Case.objective.ilike(like)))
        ).scalars().all()
        results["evidence"] = db.session.execute(
            db.select(Evidence).where(Evidence.title.ilike(like))
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
# BOOTSTRAP (create tables + seed initial user)
# ============================================================
def bootstrap():
    with app.app_context():
        db.create_all()
        u = app.config["INITIAL_USERNAME"]
        p = app.config["INITIAL_PASSWORD"]
        existing = db.session.execute(db.select(User).filter_by(username=u)).scalar()
        if not existing:
            user = User(username=u)
            user.set_password(p)
            db.session.add(user)
            db.session.commit()
            audit("user_seed", f"Initial user {u}", actor="system")
            print(f"✅ Seeded user: {u}")

bootstrap()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
