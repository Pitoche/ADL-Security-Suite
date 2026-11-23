from functools import wraps
from pathlib import Path

from flask import (
    Blueprint, request, render_template,
    redirect, url_for, session, abort
)
from flask_wtf.csrf import generate_csrf, validate_csrf
from werkzeug.security import check_password_hash
from wtforms.validators import ValidationError

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

HASH_FILE = Path(__file__).resolve().parents[2] / ".admin_password_hash"


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template(
            "login.html",
            csrf_token=generate_csrf,
            error=None
        )

    try:
        validate_csrf(request.form.get("csrf_token", ""))
    except ValidationError:
        abort(400)

    password = request.form.get("password", "")

    if not HASH_FILE.is_file():
        abort(503)

    stored_hash = HASH_FILE.read_text().strip()

    if check_password_hash(stored_hash, password):
        session.clear()
        session["admin_authenticated"] = True
        return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        csrf_token=generate_csrf,
        error="Invalid password."
    ), 401


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    try:
        validate_csrf(request.form.get("csrf_token", ""))
    except ValidationError:
        abort(400)

    session.clear()
    return redirect(url_for("auth.login"))
