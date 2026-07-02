"""
VulnGuard AI - Flask Application Factory
"""
import os
from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from models import db
from auth import auth_bp
from routes.scan_routes import scan_bp
from routes.dashboard_routes import dashboard_bp
from routes.report_routes import report_bp


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # CORS — only allow configured origins
    CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}},
         supports_credentials=True)

    # Rate limiting
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["300 per hour", "60 per minute"],
        storage_uri="memory://",
    )
    limiter.limit("10 per minute")(auth_bp)

    # Database
    db.init_app(app)
    with app.app_context():
        os.makedirs(os.path.join(app.instance_path), exist_ok=True)
        os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)
        try:
            db.create_all()
        except Exception:
            pass
        _seed_demo_data(app)

    # Blueprints
    app.register_blueprint(auth_bp, url_prefix="/api")
    app.register_blueprint(scan_bp, url_prefix="/api/scan")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(report_bp, url_prefix="/api/report")

    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "VulnGuard AI"}), 200

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Endpoint not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error"}), 500

    return app


def _seed_demo_data(app):
    """
    Create a demo account (demo@vulnguard.ai / Demo@12345) with sample completed
    scan data so the dashboard is populated on first run.
    """
    from models import User, Scan, Finding, ScanLog
    from auth import hash_password
    from datetime import datetime, timedelta
    import random

    if User.query.filter_by(email="demo@vulnguard.ai").first():
        return  # already seeded

    demo_user = User(
        username="demo",
        email="demo@vulnguard.ai",
        password_hash=hash_password("Demo@12345"),
    )
    db.session.add(demo_user)
    db.session.flush()

    sample_findings = [
        dict(title="Missing Content-Security-Policy Header", category="Security Misconfiguration",
             description="The target does not send a Content-Security-Policy header.", affected_url="http://juice-shop.local",
             severity="Medium", cvss_score=5.3, risk_explanation="Enables XSS exploitation without browser-level mitigation.",
             remediation="Set a strict CSP via response headers.", ai_insight="Start with 'default-src self' and expand.",
             owasp_mapping="A05:2021 - Security Misconfiguration", evidence="Header absent"),
        dict(title="Reflected XSS in 'q' parameter", category="Cross-Site Scripting (XSS)",
             description="Search parameter reflects user input unescaped.", affected_url="http://juice-shop.local/search?q=test",
             severity="High", cvss_score=6.1, risk_explanation="Allows JS execution in victim's browser.",
             remediation="Use context-aware output encoding.", ai_insight="Adopt auto-escaping templates.",
             owasp_mapping="A03:2021 - Injection", evidence="Marker reflected unescaped"),
        dict(title="SQL Injection in login form", category="SQL Injection",
             description="Login endpoint susceptible to SQL injection via username field.", affected_url="http://juice-shop.local/rest/user/login",
             severity="Critical", cvss_score=9.1, risk_explanation="Full database read/write access possible.",
             remediation="Use parameterized queries.", ai_insight="Never concatenate user input into SQL.",
             owasp_mapping="A03:2021 - Injection", evidence="' OR '1'='1 triggers auth bypass"),
        dict(title="Insecure Cookie: session", category="Insecure Cookies",
             description="Session cookie missing HttpOnly and Secure flags.", affected_url="http://juice-shop.local",
             severity="Medium", cvss_score=5.0, risk_explanation="JS can steal cookie; transmitted over HTTP.",
             remediation="Set Secure; HttpOnly; SameSite=Lax on cookie.", ai_insight="Audit all Set-Cookie headers.",
             owasp_mapping="A05:2021 - Security Misconfiguration", evidence="Set-Cookie: session=abc; Path=/"),
        dict(title="Missing X-Frame-Options Header", category="Clickjacking",
             description="Page can be framed by any origin.", affected_url="http://juice-shop.local",
             severity="Medium", cvss_score=4.3, risk_explanation="Clickjacking attacks possible.",
             remediation="Set X-Frame-Options: DENY.", ai_insight="Use CSP frame-ancestors as modern alternative.",
             owasp_mapping="A05:2021 - Security Misconfiguration", evidence="Header absent"),
        dict(title="CSRF token absent on feedback form", category="Cross-Site Request Forgery (CSRF)",
             description="POST form has no CSRF token field.", affected_url="http://juice-shop.local/contact",
             severity="Medium", cvss_score=5.7, risk_explanation="Forged cross-site requests possible.",
             remediation="Implement per-session CSRF tokens.", ai_insight="Use Flask-WTF CSRFProtect.",
             owasp_mapping="A01:2021 - Broken Access Control", evidence="No token field in form inputs"),
        dict(title="robots.txt Discloses Admin Path", category="Information Disclosure",
             description="Disallow: /admin in robots.txt.", affected_url="http://juice-shop.local/robots.txt",
             severity="Low", cvss_score=4.0, risk_explanation="Gives attackers a map of sensitive paths.",
             remediation="Remove sensitive paths from robots.txt; enforce auth instead.", ai_insight="Treat robots.txt as public.",
             owasp_mapping="A01:2021 - Broken Access Control", evidence="Disallow: /admin"),
        dict(title="Server Banner Disclosure", category="Information Disclosure",
             description="Server header reveals exact version string.", affected_url="http://juice-shop.local",
             severity="Low", cvss_score=3.1, risk_explanation="Allows targeted CVE lookup by attackers.",
             remediation="Configure web server to suppress detailed Server header.", ai_insight="Use generic 'Server: web' or suppress entirely.",
             owasp_mapping="A05:2021 - Security Misconfiguration", evidence="Server: nginx/1.18.0"),
    ]

    scan = Scan(
        user_id=demo_user.id,
        target_url="http://juice-shop.local:3000",
        scan_type="standard",
        scan_depth=2,
        status="completed",
        progress=100,
        pages_crawled=18,
        started_at=datetime.utcnow() - timedelta(hours=2),
        completed_at=datetime.utcnow() - timedelta(hours=1, minutes=45),
    )
    db.session.add(scan)
    db.session.flush()

    for fd in sample_findings:
        db.session.add(Finding(scan_id=scan.id, **fd))

    db.session.add(ScanLog(scan_id=scan.id, message="Demo scan data seeded for dashboard preview.", level="info"))
    db.session.commit()


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
