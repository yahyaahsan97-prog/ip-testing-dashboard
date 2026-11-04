import os
import csv
import io
import sqlite3
import hmac
import ipaddress

from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, request, Response, make_response,
    render_template_string, abort
)
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

SITE_NAME = "IP Testing Dashboard"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
DB_PATH = "/tmp/iplogs.db"

if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD is missing")

def connect():
    con = sqlite3.connect(DB_PATH)
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
            response = make_response("Login required", 401)
            response.headers["WWW-Authenticate"] = (
                'Basic realm="Private Dashboard"'
            )
            return response

        return fn(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>{{ name }}</title>
      <style>
        body {
          font-family: Arial;
          background: #f3f6fb;
          color: #172033;
          display: grid;
          place-items: center;
          min-height: 90vh;
        }
        .card {
          background: white;
          padding: 30px;
          border-radius: 16px;
          max-width: 420px;
          width: 85%;
          box-shadow: 0 5px 25px #0001;
        }
        h1 { color: #2563eb; }
        button {
          background: #2563eb;
          color: white;
          padding: 12px 20px;
          border: 0;
          border-radius: 8px;
          cursor: pointer;
        }
      </style>
    </head>
    <body>
      <main class="card">
        <h1>{{ name }}</h1>
        <p>Network testing and visitor diagnostics.</p>
        <p>
          If you agree, this website will record your
          IP address and visit timestamp.
        </p>
        <p>Records are retained for up to seven days.</p>
        <form action="/consent" method="POST">
          <label>
            <input type="checkbox" name="agree"
                   value="yes" required>
            I consent to IP address collection.
          </label>
          <p><button type="submit">Agree and continue</button></p>
        </form>
      </main>
    </body>
    </html>
    """, name=SITE_NAME)


@app.route("/consent", methods=["POST"])
def consent():
    if request.form.get("agree") != "yes":
        abort(400)

    try:
        visitor_ip = str(
            ipaddress.ip_address(request.remote_addr)
        )
    except ValueError:
        abort(400, "Unable to verify visitor IP")

    timestamp = datetime.now(timezone.utc).isoformat()

    cleanup()

    with connect() as con:
        con.execute(
            "INSERT INTO logs (ip, timestamp) VALUES (?, ?)",
            (visitor_ip, timestamp)
        )

    return """
    <html>
    <body style="font-family:Arial;text-align:center;padding:70px">
      <h1>Thank you!</h1>
      <p>Your consented test visit was recorded.</p>
      <a href="/">Return home</a>
    </body>
    </html>
    """


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
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>{{ name }}</title>
      <style>
        body {
          font-family: Arial;
          background: #f3f6fb;
          color: #172033;
          padding: 25px;
        }
        h1 { color: #2563eb; }
        .stats {
          display: flex;
          gap: 15px;
          flex-wrap: wrap;
        }
        .stat {
          background: white;
          padding: 20px;
          border-radius: 12px;
          flex: 1;
          min-width: 130px;
        }
        .number {
          font-size: 30px;
          color: #2563eb;
          font-weight: bold;
        }
        .table-wrap {
          background: white;
          padding: 15px;
          margin-top: 25px;
          border-radius: 12px;
          overflow-x: auto;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          text-align: left;
        }
        th, td {
          padding: 13px;
          border-bottom: 1px solid #eee;
          white-space: nowrap;
        }
        .button {
          display: inline-block;
          background: #2563eb;
          color: white;
          padding: 12px 18px;
          border-radius: 8px;
          text-decoration: none;
          margin-top: 15px;
        }
      </style>
    </head>
    <body>
      <h1>{{ name }}</h1>
      <p>Private visitor testing dashboard</p>

      <div class="stats">
        <div class="stat">
          Total visits
          <div class="number">{{ total }}</div>
        </div>
        <div class="stat">
          Unique IPs
          <div class="number">{{ unique }}</div>
        </div>
        <div class="stat">
          Recent records
          <div class="number">{{ logs|length }}</div>
        </div>
      </div>

      <a class="button" href="/export">Download CSV</a>

      <div class="table-wrap">
        <h2>IP Address History</h2>
        <table>
          <tr>
            <th>ID</th>
            <th>IP Address</th>
            <th>UTC Timestamp</th>
          </tr>
          {% for log in logs %}
          <tr>
            <td>{{ log.id }}</td>
            <td>{{ log.ip }}</td>
            <td>{{ log.timestamp }}</td>
          </tr>
          {% else %}
          <tr><td colspan="3">No visits recorded yet.</td></tr>
          {% endfor %}
        </table>
      </div>

      <p>Data retention: 7 days.</p>
    </body>
    </html>
    """, name=SITE_NAME, total=total,
         unique=unique, logs=logs)


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
            "attachment; filename=visitor-history.csv"
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
