import secrets
import jwt
import datetime
from flask import Blueprint, request, jsonify, current_app
from flask_mail import Message
from models import db, User, Challenge, OTP
from extensions import db, bcrypt
from utils import generate_challenge, hash_response, generate_otp

auth_routes = Blueprint('auth', __name__)

@auth_routes.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    # check user exists
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists"}), 400

    # Generate unique salt
    salt = secrets.token_hex(8)

    # SECURE: Salted Hashing for the Challenge Secret
    import hashlib
    secret = hashlib.sha256((password + salt).encode()).hexdigest()

    user = User(username=username, password_hash=secret, email=email, salt=salt)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully", "status": "secure"})

@auth_routes.route('/login-challenge', methods=['POST'])
def login_challenge():
    data = request.json
    username = data.get('username')

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    challenge = generate_challenge()

    # store challenge in DB
    challenge_entry = Challenge(username=username, challenge=challenge)
    db.session.add(challenge_entry)
    db.session.commit()

    return jsonify({
        "challenge": challenge,
        "salt": user.salt, # Send salt to client for hashing
        "message": "Challenge generated"
    })

@auth_routes.route('/login-verify', methods=['POST'])
def login_verify():
    data = request.json
    username = data.get('username')
    client_response = data.get('response')
    challenge_value = data.get('challenge')

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # find challenge
    challenge_entry = Challenge.query.filter_by(
        username=username,
        challenge=challenge_value,
        used=False
    ).first()

    if not challenge_entry:
        return jsonify({"message": "Invalid or reused challenge (Replay Attack detected!)"}), 400

    # mark challenge as used (prevent replay)
    challenge_entry.used = True
    db.session.commit()

    # compute expected response
    # NOTE: we compare using stored hashed password (important!)
    expected_response = hash_response(user.password_hash, challenge_value)

    if expected_response != client_response:
        return jsonify({"message": "Authentication failed"}), 401

    # SECURE: Generate and store OTP
    otp_code = generate_otp()
    
    # REAL EMAIL SENDING
    target_email = user.email
    email_status = "not sent"
    masked_email = "your email" 
    
    if target_email:
        masked_email = f"{target_email[0]}***@{target_email.split('@')[-1]}"
        try:
            from app import mail
            msg = Message(
                "Your SecureLog OTP",
                recipients=[target_email],
                body=f"Your verification code is: {otp_code}\n\nThis code will expire in 10 minutes."
            )
            mail.send(msg)
            email_status = f"sent to {masked_email}"
        except Exception as e:
            # This is where we catch SMTP errors if credentials are missing
            print(f"ERROR: Failed to send email: {e}")
            email_status = f"delivery failed (check your .env file)"
    else:
        email_status = "no email provided"
    
    otp_entry = OTP(username=username, otp_code=otp_code)
    db.session.add(otp_entry)
    db.session.commit()

    return jsonify({
        "message": f"OTP Verification Step: {email_status}",
        "status": "otp_sent",
        "email_status": email_status
    })

@auth_routes.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    username = data.get('username')
    otp_code = data.get('otp')

    otp_entry = OTP.query.filter_by(
        username=username, 
        otp_code=otp_code, 
        is_used=False
    ).order_by(OTP.created_at.desc()).first()

    if not otp_entry:
        return jsonify({"message": "Invalid or expired OTP"}), 400

    # Mark as used
    otp_entry.is_used = True
    db.session.commit()

    # SESSION MANAGEMENT: Generate JWT Token
    token = jwt.encode({
        'user': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, current_app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        "message": "OTP verified. Login successful!",
        "token": token
    })

