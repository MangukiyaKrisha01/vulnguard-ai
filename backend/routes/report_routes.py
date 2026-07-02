"""
VulnGuard AI - Report export routes (PDF, JSON, CSV)
"""
import csv
import io
import json
import os

from flask import Blueprint, jsonify, request, send_file, current_app

from auth import token_required
from models import Scan, Finding
from reports.pdf_generator import generate_pdf_report

report_bp = Blueprint("report", __name__)


def _get_scan_or_404(scan_id, user_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
    return scan


@report_bp.route("/download/<int:scan_id>/pdf", methods=["GET"])
@token_required
def download_pdf(scan_id):
    scan = _get_scan_or_404(scan_id, request.current_user.id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.status != "completed":
        return jsonify({"error": "Scan is not completed yet"}), 400

    findings = Finding.query.filter_by(scan_id=scan_id).order_by(Finding.cvss_score.desc()).all()
    reports_dir = current_app.config["REPORTS_DIR"]
    os.makedirs(reports_dir, exist_ok=True)
    output_path = os.path.join(reports_dir, f"vulnguard_scan_{scan_id}.pdf")

    try:
        generate_pdf_report(scan, findings, output_path)
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {e}"}), 500

    return send_file(output_path, as_attachment=True,
                     download_name=f"VulnGuard_Report_Scan_{scan_id}.pdf",
                     mimetype="application/pdf")


@report_bp.route("/download/<int:scan_id>/json", methods=["GET"])
@token_required
def download_json(scan_id):
    scan = _get_scan_or_404(scan_id, request.current_user.id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = Finding.query.filter_by(scan_id=scan_id).order_by(Finding.cvss_score.desc()).all()
    payload = {
        "scan": scan.to_dict(),
        "findings": [f.to_dict() for f in findings],
    }
    buf = io.BytesIO(json.dumps(payload, indent=2).encode("utf-8"))
    buf.seek(0)
    return send_file(buf, as_attachment=True,
                     download_name=f"VulnGuard_Report_Scan_{scan_id}.json",
                     mimetype="application/json")


@report_bp.route("/download/<int:scan_id>/csv", methods=["GET"])
@token_required
def download_csv(scan_id):
    scan = _get_scan_or_404(scan_id, request.current_user.id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = Finding.query.filter_by(scan_id=scan_id).order_by(Finding.cvss_score.desc()).all()

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        "id", "title", "category", "severity", "cvss_score",
        "affected_url", "owasp_mapping", "description",
        "risk_explanation", "remediation", "ai_insight", "evidence"
    ])
    writer.writeheader()
    for f in findings:
        writer.writerow(f.to_dict())

    byte_buf = io.BytesIO(buf.getvalue().encode("utf-8"))
    byte_buf.seek(0)
    return send_file(byte_buf, as_attachment=True,
                     download_name=f"VulnGuard_Report_Scan_{scan_id}.csv",
                     mimetype="text/csv")
