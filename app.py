import os
import re
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, redirect, url_for, render_template, flash, send_file, abort
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "evidence"
REPORT_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "scamsathi.db"
for directory in (DATA_DIR, UPLOAD_DIR, REPORT_DIR):
    directory.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SCAMSATHI_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 MB request limit
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt", "eml", "webp"}
MAX_TEXT_LENGTH = 8000


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            description TEXT NOT NULL,
            analysis_score INTEGER NOT NULL DEFAULT 0,
            analysis_level TEXT NOT NULL DEFAULT 'Unassessed',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            added_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            event_text TEXT NOT NULL,
            event_time TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        );
        """)


def analyze_text(text):
    """Transparent heuristic analysis; this is not a definitive malware verdict."""
    text = (text or "")[:MAX_TEXT_LENGTH]
    lowered = text.lower()
    indicators = []
    score = 0

    rules = [
        (r"\b(urgent|immediately|act now|within 24 hours|limited time)\b",
         "Urgency or pressure language", 15),
        (r"\b(otp|one[- ]time password|password|pin|cvv|card number)\b",
         "Requests or references to sensitive authentication/payment data", 20),
        (r"\b(prize|winner|won|lottery|giveaway|claim your reward)\b",
         "Unexpected prize or reward language", 15),
        (r"\b(account (will be|has been) (blocked|suspended|closed)|verify your account)\b",
         "Account threat or verification pressure", 20),
        (r"\b(send money|pay fee|processing fee|transfer funds|refund fee)\b",
         "Payment or transfer request", 20),
        (r"\b(guaranteed returns|double your money|investment secret)\b",
         "Unrealistic financial promise", 15),
        (r"\b(click here|open this link|download attachment)\b",
         "Prompt to click a link or open an attachment", 10),
        (r"\b(crypto|cryptocurrency|wallet seed|recovery phrase)\b",
         "Cryptocurrency or wallet-related terms", 10),
    ]
    for pattern, label, points in rules:
        if re.search(pattern, lowered):
            indicators.append({"label": label, "points": points})
            score += points

    urls = re.findall(r"https?://[^\s<>\]\)\"']+", text, flags=re.IGNORECASE)
    for raw_url in urls:
        cleaned = raw_url.rstrip(".,!?;:")
        try:
            parsed = urlparse(cleaned)
            host = (parsed.hostname or "").lower()
            if parsed.scheme != "https":
                indicators.append({"label": f"URL does not use HTTPS: {host or cleaned}", "points": 10})
                score += 10
            if host and (host.startswith("xn--") or ".xn--" in host):
                indicators.append({"label": f"Internationalized/punycode domain to inspect: {host}", "points": 15})
                score += 15
            if host and re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                indicators.append({"label": f"URL uses an IP address instead of a normal domain: {host}", "points": 15})
                score += 15
            if len(cleaned) > 100:
                indicators.append({"label": "Unusually long URL", "points": 5})
                score += 5
        except ValueError:
            indicators.append({"label": "URL could not be parsed cleanly", "points": 5})
            score += 5

    score = min(score, 100)
    if score >= 60:
        level = "High"
        advice = "Do not interact with the message or link. Verify independently through the organisation's official website or phone number."
    elif score >= 30:
        level = "Elevated"
        advice = "Pause and verify the sender using a trusted, separate channel before taking action."
    else:
        level = "Lower indicator count"
        advice = "This heuristic found fewer warning signs, but that does not mean the message is safe. Verify unexpected requests independently."

    if not indicators:
        indicators.append({"label": "No configured warning pattern matched", "points": 0})
    return {
        "score": score,
        "level": level,
        "indicators": indicators,
        "advice": advice,
        "urls": urls,
        "disclaimer": "This is a transparent, rule-based educational screening tool, not a definitive scam or malware detector."
    }


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.errorhandler(413)
def too_large(_error):
    flash("Upload rejected: total request size must be under 8 MB.", "error")
    return redirect(request.referrer or url_for("index"))


@app.route("/")
def index():
    with db() as conn:
        incidents = conn.execute("""
            SELECT i.*, (SELECT COUNT(*) FROM evidence e WHERE e.incident_id=i.id) AS evidence_count
            FROM incidents i ORDER BY i.id DESC LIMIT 10
        """).fetchall()
    return render_template("index.html", incidents=incidents)


@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    result = None
    source_text = ""
    if request.method == "POST":
        source_text = request.form.get("message", "")[:MAX_TEXT_LENGTH]
        if not source_text.strip():
            flash("Paste a message or URL to analyze.", "error")
        else:
            result = analyze_text(source_text)
    return render_template("analyze.html", result=result, source_text=source_text)


@app.route("/incidents/new", methods=["GET", "POST"])
def new_incident():
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:120]
        incident_type = request.form.get("incident_type", "Suspicious message").strip()[:80]
        description = request.form.get("description", "").strip()[:MAX_TEXT_LENGTH]
        if not title or not description:
            flash("Incident title and description are required.", "error")
            return render_template("new_incident.html", title=title, incident_type=incident_type, description=description)
        analysis = analyze_text(description)
        with db() as conn:
            cursor = conn.execute(
                "INSERT INTO incidents(title, incident_type, description, analysis_score, analysis_level, created_at) VALUES(?,?,?,?,?,?)",
                (title, incident_type, description, analysis["score"], analysis["level"], now_iso())
            )
            incident_id = cursor.lastrowid
            conn.execute(
                "INSERT INTO events(incident_id, event_text, event_time) VALUES(?,?,?)",
                (incident_id, "Incident record created", now_iso())
            )
        flash("Incident created. You can now attach evidence and add timeline events.", "success")
        return redirect(url_for("incident_detail", incident_id=incident_id))
    return render_template("new_incident.html", title="", incident_type="Suspicious message", description="")


@app.route("/incidents/<int:incident_id>")
def incident_detail(incident_id):
    with db() as conn:
        incident = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if incident is None:
            abort(404)
        evidence = conn.execute("SELECT * FROM evidence WHERE incident_id=? ORDER BY id DESC", (incident_id,)).fetchall()
        events = conn.execute("SELECT * FROM events WHERE incident_id=? ORDER BY id DESC", (incident_id,)).fetchall()
    analysis = analyze_text(incident["description"])
    return render_template("incident.html", incident=incident, evidence=evidence, events=events, analysis=analysis)


@app.route("/incidents/<int:incident_id>/evidence", methods=["POST"])
def upload_evidence(incident_id):
    with db() as conn:
        incident = conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if incident is None:
        abort(404)
    upload = request.files.get("evidence")
    if not upload or not upload.filename:
        flash("Choose a file first.", "error")
        return redirect(url_for("incident_detail", incident_id=incident_id))
    if not allowed_file(upload.filename):
        flash("Unsupported file type. Allowed: PNG, JPG, JPEG, WEBP, PDF, TXT, EML.", "error")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    original = secure_filename(upload.filename) or "evidence_file"
    stored = f"{secrets.token_hex(12)}_{original}"
    destination = UPLOAD_DIR / stored
    upload.save(destination)
    digest = sha256_file(destination)
    size = destination.stat().st_size
    with db() as conn:
        conn.execute(
            "INSERT INTO evidence(incident_id, original_name, stored_name, sha256, size_bytes, added_at) VALUES(?,?,?,?,?,?)",
            (incident_id, original, stored, digest, size, now_iso())
        )
        conn.execute(
            "INSERT INTO events(incident_id, event_text, event_time) VALUES(?,?,?)",
            (incident_id, f"Evidence added: {original}; SHA-256 recorded", now_iso())
        )
    flash("Evidence saved and SHA-256 hash recorded.", "success")
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/events", methods=["POST"])
def add_event(incident_id):
    event_text = request.form.get("event_text", "").strip()[:500]
    with db() as conn:
        exists = conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not exists:
            abort(404)
        if event_text:
            conn.execute("INSERT INTO events(incident_id, event_text, event_time) VALUES(?,?,?)",
                         (incident_id, event_text, now_iso()))
    if event_text:
        flash("Timeline event added.", "success")
    else:
        flash("Enter a timeline event.", "error")
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/evidence/<int:evidence_id>/verify")
def verify_evidence(evidence_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if row is None:
        abort(404)
    path = UPLOAD_DIR / row["stored_name"]
    if not path.is_file():
        current_hash, status = "FILE MISSING", "Missing"
    else:
        current_hash = sha256_file(path)
        status = "MATCH" if current_hash == row["sha256"] else "MISMATCH"
    return render_template("verify.html", evidence=row, current_hash=current_hash, status=status)


@app.route("/incidents/<int:incident_id>/report")
def download_report(incident_id):
    with db() as conn:
        incident = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if incident is None:
            abort(404)
        evidence = conn.execute("SELECT * FROM evidence WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()
        events = conn.execute("SELECT * FROM events WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()

    path = REPORT_DIR / f"scamsathi_incident_{incident_id}.pdf"
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallText", parent=styles["BodyText"], fontSize=8, leading=10, wordWrap="CJK"))
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm)
    story = [
        Paragraph("ScamSathi — Digital Incident Report", styles["Title"]),
        Paragraph("Educational incident summary generated by ScamSathi. This is not a legal finding or proof of criminal activity.", styles["SmallText"]),
        Spacer(1, 8),
        Paragraph(f"<b>Incident #{incident_id}: {escape_html(incident['title'])}</b>", styles["Heading2"]),
        Paragraph(f"<b>Type:</b> {escape_html(incident['incident_type'])}", styles["BodyText"]),
        Paragraph(f"<b>Created:</b> {escape_html(incident['created_at'])}", styles["BodyText"]),
        Paragraph(f"<b>Heuristic indicator score:</b> {incident['analysis_score']}/100 ({escape_html(incident['analysis_level'])})", styles["BodyText"]),
        Spacer(1, 8),
        Paragraph("Incident description", styles["Heading3"]),
        Paragraph(escape_html(incident["description"]).replace("\n", "<br/>"), styles["BodyText"]),
        Spacer(1, 8),
        Paragraph("Evidence inventory", styles["Heading3"]),
    ]
    if evidence:
        table_data = [["File", "Size (bytes)", "SHA-256", "Added"]]
        for item in evidence:
            table_data.append([
                Paragraph(escape_html(item["original_name"]), styles["SmallText"]),
                str(item["size_bytes"]),
                Paragraph(item["sha256"], styles["SmallText"]),
                Paragraph(escape_html(item["added_at"]), styles["SmallText"])
            ])
        table = Table(table_data, colWidths=[42*mm, 22*mm, 68*mm, 30*mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#14213d")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.35, colors.grey),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No evidence files have been attached.", styles["BodyText"]))
    story += [Spacer(1, 8), Paragraph("Timeline", styles["Heading3"])]
    for event in events:
        story.append(Paragraph(f"• {escape_html(event['event_time'])}: {escape_html(event['event_text'])}", styles["SmallText"]))
        story.append(Spacer(1, 3))
    story += [
        Spacer(1, 10),
        Paragraph("Limitations and safety", styles["Heading3"]),
        Paragraph("The score is based on transparent text-pattern heuristics and is not a machine-learning verdict. A low score does not prove a message is safe. SHA-256 matching indicates that the current file bytes match the recorded hash; it does not prove the evidence's source, authenticity, or chain of custody. Preserve original material and follow official reporting guidance.", styles["SmallText"])
    ]
    doc.build(story)
    return send_file(path, as_attachment=True, download_name=path.name, mimetype="application/pdf")


def escape_html(value):
    value = str(value or "")
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")


@app.route("/health")
def health():
    return {"status": "ok", "app": "ScamSathi"}


init_db()

if __name__ == "__main__":
    # Local development only. For public hosting, use a production WSGI server and HTTPS.
    app.run(debug=False, host="127.0.0.1", port=5000)
