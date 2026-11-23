from modules.auth.routes import auth_bp
from modules.iot.routes import iot_bp

import os
from pathlib import Path
import sqlite3
from flask import Flask, render_template

app = Flask(__name__)

# Local session configuration
app.config["SECRET_KEY"] = (
    Path(__file__).resolve().parent / ".flask_secret_key"
).read_text().strip()

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


app.register_blueprint(iot_bp)
app.register_blueprint(auth_bp)

GUARD_DB = "/home/angel/ADL-TEST-GUARD/instance/adl_guard.db"


@app.route("/")
def dashboard():
    return render_template(
        "dashboard.html",
        iot_url=os.environ.get(
            "ADL_IOT_URL",
            "http://127.0.0.1:5000"
        )
    )


@app.route("/reports")
def reports():
    assessments = []
    guard_error = None

    try:
        connection = sqlite3.connect(
            f"file:{GUARD_DB}?mode=ro",
            uri=True,
            timeout=5
        )
        connection.row_factory = sqlite3.Row

        try:
            rows = connection.execute("""
                SELECT
                    test_id,
                    test_name,
                    test_area,
                    execution_state,
                    start_time,
                    end_time,
                    manual_critical_alert
                FROM test_runs
                ORDER BY start_time DESC
                LIMIT 100
            """).fetchall()

            assessments = [dict(row) for row in rows]
        finally:
            connection.close()

    except (sqlite3.Error, OSError) as error:
        app.logger.error("Guard database read failed: %s", error)
        guard_error = "Guard assessment data is currently unavailable."

    return render_template(
        "reports.html",
        assessments=assessments,
        guard_error=guard_error
    )


@app.route("/health")
def health():
    return {"status": "ok", "application": "ADL Security Suite"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
