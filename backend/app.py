"""
Cybersecurity Awareness & Threat Intelligence Dashboard
Main Flask Application Server
Module: backend.app
"""

import os
import sys

# Ensure repository root is on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS

from backend.models.database import init_db, DB_PATH
from backend.routes.threat_routes import threat_bp
from backend.routes.indicator_routes import indicator_bp
from backend.routes.alert_routes import alert_bp
from backend.routes.vulnerability_routes import vulnerability_bp
from backend.routes.awareness_routes import awareness_bp
from backend.routes.dashboard_routes import dashboard_bp

def create_app():
    """Application factory for the defensive cybersecurity platform."""
    frontend_dir = os.path.join(BASE_DIR, "frontend")
    app = Flask(__name__, static_folder=frontend_dir, static_url_path="")
    CORS(app)

    # Initialize database if needed
    if not os.path.exists(DB_PATH):
        print(f"[*] Threat Intelligence database not found at {DB_PATH}. Initializing & seeding...")
        init_db(DB_PATH)
    else:
        # Quick validation
        init_db(DB_PATH, force_reseed=False)

    # Register API Blueprints
    app.register_blueprint(threat_bp)
    app.register_blueprint(indicator_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(vulnerability_bp)
    app.register_blueprint(awareness_bp)
    app.register_blueprint(dashboard_bp)

    # Health Check Endpoint
    @app.route("/api/health", methods=["GET"])
    def health_check():
        return jsonify({
            "status": "healthy",
            "service": "Cybersecurity Awareness & Threat Intelligence Platform",
            "version": "1.0.0",
            "mode": "Defensive Telemetry & Awareness Education",
            "safety_directive": "Active outbound network probing is permanently disabled."
        }), 200

    # Frontend UI Routes
    @app.route("/", methods=["GET"])
    def serve_index():
        return send_from_directory(frontend_dir, "index.html")

    @app.route("/threat-dashboard", methods=["GET"])
    def serve_dashboard():
        return send_from_directory(frontend_dir, "threat-dashboard.html")

    @app.route("/threat-details", methods=["GET"])
    def serve_details():
        return send_from_directory(frontend_dir, "threat-details.html")

    @app.route("/awareness", methods=["GET"])
    def serve_awareness():
        return send_from_directory(frontend_dir, "awareness.html")

    @app.route("/quiz", methods=["GET"])
    def serve_quiz():
        return send_from_directory(frontend_dir, "quiz.html")

    @app.route("/css/<path:path>", methods=["GET"])
    def serve_css(path):
        return send_from_directory(os.path.join(frontend_dir, "css"), path)

    @app.route("/js/<path:path>", methods=["GET"])
    def serve_js(path):
        return send_from_directory(os.path.join(frontend_dir, "js"), path)

    # Global Error Handlers
    @app.errorhandler(404)
    def handle_404(e):
        return jsonify({"status": "error", "status_code": 404, "message": "API endpoint or resource not found."}), 404

    @app.errorhandler(500)
    def handle_500(e):
        return jsonify({"status": "error", "status_code": 500, "message": "Internal server error occurred."}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"""
    ========================================================================
    * CYBERSECURITY AWARENESS & THREAT INTELLIGENCE DASHBOARD ACTIVE *
    * Host: http://{host}:{port}
    * SOC Dashboard: http://{host}:{port}/threat-dashboard
    * Awareness Center: http://{host}:{port}/awareness
    * Security Quiz: http://{host}:{port}/quiz
    * REST API Documentation: http://{host}:{port}/api/health
    * Mode: DEFENSIVE ONLY (Safe Synthetic Telemetry)
    ========================================================================
    """)
    app.run(host=host, port=port, debug=True)
