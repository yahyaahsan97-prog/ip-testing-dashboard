import os
import csv
import io
import sqlite3
import hmac
import ipaddress

from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, request, Response, abort,
    render_template_string, make_response
)
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# Trust the single reverse proxy in front of the Render service.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

SITE_NAME = "WARERA"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
DB_PATH = os.environ.get("DB_PATH", "/tmp/iplogs.db")

if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD environment variable is required")


def connect():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with connect() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)


def cleanup():
    cutoff = (
        datetime.now(timezone.utc) -
        timedelta(days=7)
    ).isoformat()

    with connect() as con:
        con.execute(
            "DELETE FROM logs WHERE timestamp < ?",
            (cutoff,)
        )


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.authorization

        valid = (
            auth is not None
            and auth.username == "admin"
            and hmac.compare_digest(
                auth.password or "",
                ADMIN_PASSWORD
            )
        )

        if not valid:
            response = make_response(
                "Admin authentication required", 401
            )
            response.headers["WWW-Authenticate"] = (
                'Basic realm="WARERA Admin"'
            )
            return response

        return fn(*args, **kwargs)

    return wrapper


BASE_STYLE = """
<style>
* { box-sizing: border-box; }

body {
    margin: 0;
    padding: 24px;
    background: #080808;
    color: #eeeeee;
    font-family: Arial, sans-serif;
}

.container {
    max-width: 1050px;
    margin: auto;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #292929;
    padding-bottom: 20px;
    margin-bottom: 28px;
}

.logo {
    font-size: 27px;
    font-weight: 900;
    letter-spacing: 3px;
}

.muted { color: #888888; }

.card {
    background: #141414;
    border: 1px solid #292929;
    border-radius: 13px;
    padding: 22px;
}

.stats {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 15px;
    margin-bottom: 24px;
}

.stat-number {
    font-size: 34px;
    font-weight: bold;
    margin-top: 12px;
}

.btn {
    display: inline-block;
    background: #eeeeee;
    color: #080808;
    padding: 12px 18px;
    border: 0;
    border-radius: 7px;
    text-decoration: none;
    font-weight: bold;
    cursor: pointer;
}

input[type=checkbox] {
    accent-color: white;
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 450px;
}

th, td {
    padding: 15px 10px;
    text-align: left;
    border-bottom: 1px solid #292929;
    font-size: 13px;
}

th { color: #999999; }

.table-wrap {
    overflow-x: auto;
    margin-top: 20px;
}

a { color: white; }

@media(max-width: 600px) {
    body { padding: 16px; }
    .stats { grid-template-columns: 1fr 1fr; }
    .stat-number { font-size: 26px; }
    .logo { font-size: 22px; }
}
</style>
"""


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>WARERA | Network Testing</title>
        """ + BASE_STYLE + """
    </head>
    <body>
    <main class="container">
        <header>
            <div class="logo">WARERA.</div>
            <span class="muted">NETWORK TESTING</span>
        </header>

        <section class="card">
            <p class="muted">VISITOR CONSENT</p>
            <h1>Network diagnostics</h1>

            <p class="muted">
                This test records your IP address and visit time
                only after you explicitly agree.
            </p>

            <p class="muted">
                Records are retained for up to seven days.
                No GPS location or device fingerprinting is collected.
            </p>

            <form method="POST" action="/consent">
                <label>
                    <input type="checkbox" name="agree"
                           value="yes" required>
                    I agree to IP address collection for testing.
                </label>
                <p>
                    <button class="btn" type="submit">
                        AGREE & CONTINUE
                    </button>
                </p>
            </form>
        </section>
    </main>
    </body>
    </html>
    """)


@app.route("/consent", methods=["POST"])
def consent():
    if request.form.get("agree") != "yes":
        abort(400)

    try:
        visitor_ip = str(
            ipaddress.ip_address(request.remote_addr)
        )
    except ValueError:
        abort(400, "Unable to validate IP address")

    timestamp = datetime.now(timezone.utc).isoformat()

    cleanup()

    with connect() as con:
        con.execute(
            "INSERT INTO logs (ip, timestamp) VALUES (?, ?)",
            (visitor_ip, timestamp)
        )

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>WARERA | Success</title>
        """ + BASE_STYLE + """
    </head>
    <body>
    <main class="container">
        <header><div class="logo">WARERA.</div></header>
        <section class="card">
            <h1>Thank you.</h1>
            <p class="muted">
                Your consented network test visit was recorded.
            </p>
            <a href="/">RETURN HOME</a>
        </section>
    </main>
    </body>
    </html>
    """)


@app.route("/dashboard")
@admin_required
def dashboard():
    cleanup()

    with connect() as con:
        total = con.execute(
            "SELECT COUNT(*) FROM logs"
        ).fetchone()[0]

        unique = con.execute(
            "SELECT COUNT(DISTINCT ip) FROM logs"
        ).fetchone()[0]

        logs = con.execute("""
            SELECT id, ip, timestamp
            FROM logs
            ORDER BY id DESC
            LIMIT 500
        """).fetchall()

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>WARERA | Dashboard</title>
        """ + BASE_STYLE + """
    </head>
    <body>
    <main class="container">
        <header>
            <div class="logo">WARERA.</div>
            <span class="muted">ADMIN PANEL</span>
        </header>

        <h2>Visitor Dashboard</h2>
        <p class="muted">CONSENTED NETWORK TEST VISITS</p>

        <div class="stats">
            <section class="card">
                <div class="muted">TOTAL VISITS</div>
                <div class="stat-number">{{ total }}</div>
            </section>

            <section class="card">
                <div class="muted">UNIQUE IP ADDRESSES</div>
                <div class="stat-number">{{ unique }}</div>
            </section>
        </div>

        <section class="card">
            <h3>IP ADDRESS HISTORY</h3>
            <p class="muted">Latest 500 records · 7-day retention</p>

            <a href="/export" class="btn">DOWNLOAD CSV</a>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>IP ADDRESS</th>
                            <th>UTC TIMESTAMP</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for log in logs %}
                        <tr>
                            <td>{{ log.id }}</td>
                            <td>{{ log.ip }}</td>
                            <td>{{ log.timestamp }}</td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="3">No consented visits yet.</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>

        <p class="muted">WARERA · NETWORK TESTING</p>
    </main>
    </body>
    </html>
    """, total=total, unique=unique, logs=logs)


@app.route("/export")
@admin_required
def export():
    cleanup()

    with connect() as con:
        logs = con.execute("""
            SELECT id, ip, timestamp
            FROM logs ORDER BY id DESC
        """).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["ID", "IP Address", "UTC Timestamp"])

    for log in logs:
        writer.writerow([
            log["id"], log["ip"], log["timestamp"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=warera-visitor-history.csv"
        }
    )


@app.route("/health")
def health():
    return {"status": "ok"}


init_db()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
