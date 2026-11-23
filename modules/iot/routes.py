from pathlib import Path
from modules.auth.routes import login_required
from flask import Blueprint, jsonify, current_app
from flask_wtf.csrf import generate_csrf, validate_csrf
from wtforms.validators import ValidationError


DEFAULT_IOT_DB = "/home/angel/ADL-TOOL-Repository/ADL-TOOL-DB.db"


def get_iot_db_path():
    return current_app.config.get("IOT_DB_PATH", DEFAULT_IOT_DB)


iot_bp = Blueprint("iot", __name__, url_prefix="/iot")


@iot_bp.route("/")
def index():
    return jsonify({
        "module": "IoT Vulnerability Assessment",
        "status": "available",
        "integration": "initial"
    })


@iot_bp.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "module": "iot"
    })


@iot_bp.route("/projects")
def projects():
    import sqlite3
    from flask import render_template

    db_path = get_iot_db_path()

    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT id, project_name, created_at,
                   docker_mode, log_level
            FROM projects
            ORDER BY id DESC
        """).fetchall()

    return render_template("iot_projects.html", projects=rows)


@iot_bp.route("/project/<int:project_id>")
def project_details(project_id):
    import sqlite3
    from flask import abort, render_template

    db_path = get_iot_db_path()

    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        project = conn.execute(
            "SELECT * FROM projects WHERE id = ?",
            (project_id,)
        ).fetchone()

    if project is None:
        abort(404)

    return render_template(
        "iot_project_details.html",
        project=dict(project)
    )


@iot_bp.route("/create-project", methods=["GET", "POST"])
@login_required
def create_project():
    import configparser
    import sqlite3
    from datetime import datetime
    from flask import request, render_template, redirect, url_for

    # Keep live database writes disabled during integration testing.
    if not current_app.config.get("IOT_ALLOW_PROJECT_WRITES", False):
        return "Project creation is disabled during integration testing.", 403

    if request.method == "GET":
        return render_template(
            "iot_create_project.html",
            csrf_token=generate_csrf
        )

    try:
        validate_csrf(request.form.get("csrf_token", ""))
    except ValidationError:
        return "Invalid or missing CSRF token", 400

    name = request.form.get("project_name", "").strip()
    log_level = request.form.get("log_level", "INFO").strip()
    docker_mode = request.form.get("docker_mode", "local").strip()
    docker_host_ip = request.form.get("docker_host_ip", "").strip()

    try:
        retention = int(request.form.get("log_retention_days", "30"))
    except (ValueError, TypeError):
        return "Invalid log retention value", 400

    if not name or len(name) > 200:
        return "Project name must contain 1–200 characters", 400

    if not 1 <= retention <= 3650:
        return "Log retention must be between 1 and 3650 days", 400

    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        return "Invalid logging level", 400

    if docker_mode not in {"local", "remote"}:
        return "Invalid Docker mode", 400

    config = configparser.ConfigParser()
    config_path = "/home/angel/ADL-TOOL-Repository/vul-tool/src/config.ini"

    if not config.read(config_path):
        return "Original IoT configuration unavailable", 500

    settings = config["DEFAULT"]
    db_path = get_iot_db_path()

    # Production writes require separate explicit authorisation.
    is_live_db = (
        Path(db_path).resolve() == Path(DEFAULT_IOT_DB).resolve()
    )

    if is_live_db and not current_app.config.get(
        "IOT_ALLOW_LIVE_WRITES", False
    ):
        return "Live database writes are not enabled", 403

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute("""
            INSERT INTO projects (
                project_name, project_path, requirements_path,
                reports_path, db_path, log_retention_days,
                log_level, docker_mode, docker_host_ip, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            name,
            settings.get("project_path", ""),
            settings.get("requirements_path", ""),
            settings.get("reports_path", ""),
            settings.get("db_path", ""),
            retention,
            log_level,
            docker_mode,
            docker_host_ip,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        project_id = cursor.lastrowid
        conn.commit()

    return redirect(url_for("iot.project_details", project_id=project_id))
