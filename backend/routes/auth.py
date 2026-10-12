import bcrypt
from flask import Blueprint, request, jsonify, g
from sqlalchemy import func

from config import Config
from models import db
from models.models import User
from utils.jwt_utils import create_token, require_jwt, require_admin
from utils.validators import (
    sanitize_text,
    validate_email,
    validate_password,
    validate_username,
)

auth_bp = Blueprint("auth", __name__)


def _public_user(user: User) -> dict:
    """Never expose password_hash or anything else sensitive."""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
    }


def _auth_payload(user: User):
    token = create_token(user.id, user.email, user.role)
    return {
        "token": token,
        "expires_in": Config.JWT_EXPIRY_HOURS * 3600,
        "user": _public_user(user),
    }


@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = sanitize_text(data.get("username", "") or data.get("name", ""), 80)
    email = sanitize_text(data.get("email", ""), 255).lower()
    password = data.get("password", "") or ""
    confirm = data.get("confirm_password", data.get("confirmPassword", ""))

    if not validate_username(username):
        return jsonify({
            "error": "Username must be 3-30 characters and may only contain "
                     "letters, numbers, dot, underscore or hyphen."
        }), 400

    if not validate_email(email):
        return jsonify({"error": "Please provide a valid email address."}), 400

    ok, message = validate_password(password)
    if not ok:
        return jsonify({"error": message}), 400

    # Only enforced when the client sends the field, so existing API callers
    # that post {email, password} keep working.
    if confirm is not None and confirm != "" and confirm != password:
        return jsonify({"error": "Passwords do not match."}), 400

    if User.query.filter(func.lower(User.email) == email).first():
        return jsonify({"error": "An account with that email already exists."}), 409

    if User.query.filter(func.lower(User.username) == username.lower()).first():
        return jsonify({"error": "That username is already taken."}), 409

    # The role is decided by the server only. A client-supplied "role" field is
    # ignored, otherwise anyone could register themselves as an administrator.
    role = "admin" if email in Config.ADMIN_EMAILS else "user"

    user = User(
        username=username,
        email=email,
        password_hash=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        role=role,
    )
    db.session.add(user)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Could not create the account. Please try again."}), 409

    return jsonify(_auth_payload(user)), 201


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    identifier = sanitize_text(
        data.get("email", "") or data.get("username", "") or data.get("identifier", ""),
        255,
    ).lower()
    password = data.get("password", "") or ""

    if not identifier or not password:
        return jsonify({"error": "Email/username and password are required."}), 400

    user = User.query.filter(
        (func.lower(User.email) == identifier) | (func.lower(User.username) == identifier)
    ).first()

    # Same generic message for both cases so the endpoint cannot be used to
    # enumerate which emails are registered.
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return jsonify({"error": "Invalid credentials."}), 401

    return jsonify(_auth_payload(user))


@auth_bp.get("/me")
@require_jwt
def me():
    user = User.query.get(g.current_user["id"])
    if not user:
        return jsonify({"error": "Account no longer exists."}), 401
    return jsonify({"user": _public_user(user)})


@auth_bp.post("/logout")
@require_jwt
def logout():
    # JWTs are stateless, so the authoritative action is the client discarding
    # the token. This endpoint confirms the token was valid at logout time and
    # gives the frontend a single call to make.
    return jsonify({"message": "Logged out.", "clear_token": True})


@auth_bp.get("/admin/users")
@require_admin
def admin_list_users():
    """Makes the pre-existing require_admin decorator reachable and testable."""
    users = User.query.order_by(User.id).all()
    return jsonify({"count": len(users), "users": [_public_user(u) for u in users]})
