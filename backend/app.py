"""
Application Entrypoint
Configures Flask, applies security headers, registers blueprints,
serves static frontend files, and initializes the local metadata database.
Enforces zero password logging.
"""

import os
import sys
import logging
from flask import Flask, send_from_directory
from flask_cors import CORS

from backend.routes.api import api_bp
from backend.models.database import init_db

def create_app():
    # Base paths
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frontend_dir = os.path.join(root_dir, "frontend")

    app = Flask(__name__, static_folder=frontend_dir)
    
    # Configure CORS for local security testing
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Suppress verbose request body logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)

    # Initialize SQLite schema for aggregate analytics
    init_db()

    # Register API blueprint
    app.register_blueprint(api_bp)

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Frontend routes
    @app.route("/")
    def index():
        return send_from_directory(frontend_dir, "index.html")

    @app.route("/<path:filename>")
    def static_files(filename):
        return send_from_directory(frontend_dir, filename)

    return app

if __name__ == "__main__":
    app = create_app()
    print("=" * 70)
    print("PASSWORD STRENGTH ANALYZER & SECURITY SUGGESTION TOOL")
    print("Running in defensive local analysis mode.")
    print("Zero plaintext password storage. Local in-memory processing.")
    print("Server active at: http://127.0.0.1:5000")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=True)
