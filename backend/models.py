"""
VulnGuard AI - Database models
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship("Scan", backref="owner", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {"id": self.id, "username": self.username, "email": self.email}


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), default="standard")
    scan_depth = db.Column(db.Integer, default=2)
    status = db.Column(db.String(20), default="queued")  # queued, running, completed, failed
    progress = db.Column(db.Integer, default=0)
    pages_crawled = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    error_message = db.Column(db.String(500), nullable=True)

    findings = db.relationship("Finding", backref="scan", lazy=True, cascade="all, delete-orphan")
    logs = db.relationship("ScanLog", backref="scan", lazy=True, cascade="all, delete-orphan")

    def to_dict(self, include_findings=False):
        data = {
            "id": self.id,
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "scan_depth": self.scan_depth,
            "status": self.status,
            "progress": self.progress,
            "pages_crawled": self.pages_crawled,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "severity_counts": self.severity_counts(),
            "total_findings": len(self.findings),
        }
        if include_findings:
            data["findings"] = [f.to_dict() for f in self.findings]
        return data

    def severity_counts(self):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    affected_url = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    cvss_score = db.Column(db.Float, default=0.0)
    risk_explanation = db.Column(db.Text, nullable=False)
    remediation = db.Column(db.Text, nullable=False)
    ai_insight = db.Column(db.Text, nullable=True)
    owasp_mapping = db.Column(db.String(200), nullable=False)
    evidence = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "description": self.description,
            "affected_url": self.affected_url,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "risk_explanation": self.risk_explanation,
            "remediation": self.remediation,
            "ai_insight": self.ai_insight,
            "owasp_mapping": self.owasp_mapping,
            "evidence": self.evidence,
        }


class ScanLog(db.Model):
    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    level = db.Column(db.String(20), default="info")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {"message": self.message, "level": self.level, "timestamp": self.timestamp.isoformat()}
