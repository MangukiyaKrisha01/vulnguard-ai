"""
VulnGuard AI - Scan routes
Scans run in a background thread; status/progress is polled by the frontend.
"""
import threading
from datetime import datetime

from flask import Blueprint, current_app, jsonify, request
from urllib.parse import urlparse

from auth import token_required
from models import db, Scan, Finding, ScanLog
from scanner.engine import ScanEngine

scan_bp = Blueprint("scan", __name__)


def _valid_target(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _run_scan_background(app, scan_id):
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return
        scan.status = "running"
        db.session.commit()

        def log_cb(message, level="info"):
            with app.app_context():
                log = ScanLog(scan_id=scan_id, message=message, level=level)
                db.session.add(log)
                db.session.commit()

        def progress_cb(pct):
            with app.app_context():
                s = Scan.query.get(scan_id)
                if s:
                    s.progress = pct
                    db.session.commit()

        try:
            engine = ScanEngine(
                target_url=scan.target_url,
                scan_depth=scan.scan_depth,
                max_pages=app.config["MAX_CRAWL_PAGES"],
                timeout=app.config["REQUEST_TIMEOUT"],
                rate_delay=app.config["RATE_LIMIT_DELAY"],
                log_callback=log_cb,
                progress_callback=progress_cb,
            )
            findings_data, pages_crawled = engine.crawl_and_scan()

            scan = Scan.query.get(scan_id)
            for f in findings_data:
                finding = Finding(scan_id=scan_id, **f)
                db.session.add(finding)

            scan.pages_crawled = pages_crawled
            scan.status = "completed"
            scan.progress = 100
            scan.completed_at = datetime.utcnow()
            db.session.commit()
        except Exception as e:
            scan = Scan.query.get(scan_id)
            scan.status = "failed"
            scan.error_message = str(e)[:480]
            db.session.commit()
            log_cb(f"Scan failed: {e}", "error")


@scan_bp.route("/start", methods=["POST"])
@token_required
def start_scan():
    data = request.get_json(silent=True) or {}
    target_url = (data.get("target_url") or "").strip()
    scan_type = data.get("scan_type", "standard")
    scan_depth = int(data.get("scan_depth", 2))

    if not _valid_target(target_url):
        return jsonify({"error": "Invalid target URL. Must include http:// or https://"}), 400

    scan_depth = max(0, min(scan_depth, current_app.config["MAX_CRAWL_DEPTH"]))

    scan = Scan(
        user_id=request.current_user.id,
        target_url=target_url,
        scan_type=scan_type,
        scan_depth=scan_depth,
        status="queued",
    )
    db.session.add(scan)
    db.session.commit()

    app = current_app._get_current_object()
    thread = threading.Thread(target=_run_scan_background, args=(app, scan.id), daemon=True)
    thread.start()

    return jsonify({"scan": scan.to_dict()}), 201


@scan_bp.route("/status/<int:scan_id>", methods=["GET"])
@token_required
def scan_status(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=request.current_user.id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    recent_logs = ScanLog.query.filter_by(scan_id=scan_id).order_by(ScanLog.timestamp.desc()).limit(30).all()
    return jsonify({
        "scan": scan.to_dict(),
        "logs": [l.to_dict() for l in reversed(recent_logs)],
    }), 200


@scan_bp.route("/results/<int:scan_id>", methods=["GET"])
@token_required
def scan_results(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=request.current_user.id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"scan": scan.to_dict(include_findings=True)}), 200


@scan_bp.route("/history", methods=["GET"])
@token_required
def scan_history():
    scans = Scan.query.filter_by(user_id=request.current_user.id).order_by(Scan.started_at.desc()).all()
    return jsonify({"scans": [s.to_dict() for s in scans]}), 200


@scan_bp.route("/<int:scan_id>", methods=["DELETE"])
@token_required
def delete_scan(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=request.current_user.id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"message": "Scan deleted"}), 200
