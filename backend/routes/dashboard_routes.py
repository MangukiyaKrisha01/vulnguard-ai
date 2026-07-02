"""
VulnGuard AI - Dashboard routes
"""
from flask import Blueprint, jsonify, request

from auth import token_required
from models import Scan, Finding

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/stats", methods=["GET"])
@token_required
def dashboard_stats():
    user_id = request.current_user.id
    scans = Scan.query.filter_by(user_id=user_id).all()
    scan_ids = [s.id for s in scans]

    findings = Finding.query.filter(Finding.scan_id.in_(scan_ids)).all() if scan_ids else []

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    category_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    completed = [s for s in scans if s.status == "completed"]
    recent = sorted(scans, key=lambda s: s.started_at, reverse=True)[:5]

    return jsonify({
        "total_scans": len(scans),
        "completed_scans": len(completed),
        "running_scans": len([s for s in scans if s.status == "running"]),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "recent_scans": [s.to_dict() for s in recent],
    }), 200
