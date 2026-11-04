
from flask import Flask, request, render_template_string
from datetime import datetime, timezone

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <html>
    <head>
      <title>IP Testing Dashboard</title>
      <style>
        body {
          font-family: Arial;
          background: #f3f6fb;
          text-align: center;
          padding: 80px 15px;
          color: #172033;
        }
        .card {
          background: white;
          padding: 30px;
          border-radius: 15px;
          max-width: 400px;
          margin: auto;
        }
        button {
          background: #2563eb;
          color: white;
          padding: 12px;
          border: 0;
          border-radius: 8px;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>IP Testing Dashboard</h1>
        <p>Network testing with visitor consent.</p>
        <form action="/consent" method="POST">
          <label>
            <input type="checkbox" name="agree"
                   value="yes" required>
            I agree to IP address collection.
          </label>
          <p><button>Agree and continue</button></p>
        </form>
      </div>
    </body>
    </html>
    """

@app.route("/consent", methods=["POST"])
def consent():
    if request.form.get("agree") != "yes":
        return "Consent required", 400

    ip = request.remote_addr
    timestamp = datetime.now(timezone.utc).isoformat()

    print("Consented test visit:", ip, timestamp)

    return "<h1>Thank you!</h1><p>Your test visit was recorded.</p>"

if __name__ == "__main__":
    app.run()
