import os
import time
import hmac
import hashlib
import logging
from flask import Flask, request, jsonify, abort
from functools import wraps
import re

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration from environment variables (set in Render dashboard)
SHARED_SECRET = os.environ['SHARED_SECRET']
TOKEN_EXPIRY = 300  # 5 minutes

# Mock database (replace with real DB in production)
RESET_CODES = {}

def generate_secure_token(secret: str, interval: int = 300) -> str:
    """Generate HMAC-based token"""
    time_slot = int(time.time()) // interval
    message = f"{secret}{time_slot}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"})

@app.route('/request_reset', methods=['POST'])
def handle_reset():
    """Password reset endpoint"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        abort(401, "Missing authorization")
    
    if not hmac.compare_digest(auth_header[7:], generate_secure_token(SHARED_SECRET)):
        abort(401, "Invalid token")

    email = request.json.get('email', '').lower()
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        abort(400, "Invalid email")

    # In production: Send real email. Here we just log.
    reset_code = f"{int(time.time()) % 1000000:06d}"
    RESET_CODES[email] = {
        'code': reset_code,
        'expires': time.time() + TOKEN_EXPIRY
    }
    logger.info(f"Reset code for {email}: {reset_code}")
    
    return jsonify({
        "status": "success",
        "expires_in": TOKEN_EXPIRY
    })

# Render-compatible startup
if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 8080))
    logger.info(f"Starting server on port {port}")
    serve(app, host="0.0.0.0", port=port)
