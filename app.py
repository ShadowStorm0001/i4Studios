import os
import time
import hmac
import hashlib
import logging
import smtplib
from email.message import EmailMessage
from flask import Flask, request, jsonify, abort
import re

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== SECRET CONFIGURATION (Set in Render Dashboard) =====
SHARED_SECRET = os.environ['SHARED_SECRET']          # Your auth secret
GMAIL_APP_PASS = os.environ['GMAIL_APP_PASSWORD']    # 16-digit app password
SENDER_EMAIL = os.environ['SENDER_EMAIL']            # Your Gmail address
# ========================================================

TOKEN_EXPIRY = 300  # 5 minutes
RESET_CODES = {}    # In-memory store (replace with DB in production)

def generate_secure_token(interval: int = 300) -> str:
    """Generate HMAC token using shared secret"""
    time_slot = int(time.time()) // interval
    message = f"{SHARED_SECRET}{time_slot}".encode()
    return hmac.new(SHARED_SECRET.encode(), message, hashlib.sha256).hexdigest()

def send_reset_email(to_email: str, code: str):
    """Send email via Gmail SMTP"""
    msg = EmailMessage()
    msg.set_content(f"Your reset code: {code}\nExpires in {TOKEN_EXPIRY//60} minutes.")
    msg['Subject'] = "i4Studios Password Reset"
    msg['From'] = SENDER_EMAIL
    msg['To'] = to_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, GMAIL_APP_PASS)
            smtp.send_message(msg)
    except Exception as e:
        logger.error(f"Email failed: {str(e)}")
        raise

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "service": "i4Studios"})

@app.route('/request_reset', methods=['POST'])
def handle_reset_request():
    # Authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        abort(401, "Missing auth header")
    
    if not hmac.compare_digest(auth_header[7:], generate_secure_token()):
        abort(401, "Invalid token")

    # Validation
    email = request.json.get('email', '').lower().strip()
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        abort(400, "Invalid email")

    # Generate and send code
    code = f"{int(time.time()) % 1000000:06d}"
    RESET_CODES[email] = {
        'code': code,
        'expires': time.time() + TOKEN_EXPIRY
    }
    
    send_reset_email(email, code)  # Will raise 500 on failure
    
    return jsonify({
        "status": "success",
        "code": code,  # This is the new line that sends code to client
        "expires_in": TOKEN_EXPIRY
    })

# Required for Render
application = app
