"""
Route Blueprints
CyberTrace OSINT Platform - Zambia Police Service
"""

from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.cases import cases_bp
from app.routes.investigations import investigations_bp
from app.routes.api import api_bp

__all__ = ['auth_bp', 'dashboard_bp', 'cases_bp', 'investigations_bp', 'api_bp']
