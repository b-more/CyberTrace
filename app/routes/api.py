"""
API Routes
CyberTrace OSINT Platform - Zambia Police Service

RESTful API endpoints
"""

from flask import Blueprint, jsonify, request
from flask_login import current_user
from app.utils.decorators import login_required

api_bp = Blueprint('api', __name__)


@api_bp.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'CyberTrace OSINT Platform',
        'version': '1.0.0'
    })


@api_bp.route('/stats')
@login_required
def stats():
    """Get user statistics"""
    # TODO: Implement statistics API
    return jsonify({
        'user': current_user.username,
        'stats': {
            'cases': 0,
            'investigations': 0
        }
    })
