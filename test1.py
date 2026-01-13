import os
import yaml
import paramiko
import psutil
import smtplib
import time
from email.mime.text import MIMEText
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from threading import Thread, Lock
from functools import wraps

app = Flask(__name__)
app.secret_key = "23467923487"

# -------------------------------
# Users for dashboard login
# -------------------------------
USERS = {
    "tv": "admin",
    "viewer": "ReadOnlyPass"
}

# -------------------------------
# Login required decorator
# -------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# -------------------------------
# Load server configuration
# -------------------------------
def load_servers():
    with open("servers.yml", "r") as f:
        return yaml.safe_load(f)["servers"]

servers = load_servers()

# -------------------------------
# Email Alert Configuration
# -------------------------------
SMTP_SERVER = "smtp.zoho.com"
SMTP_PORT = 587
EMAIL_SENDER = "no-reply@payvantage.com.ng"
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVERS = ["infrastructure@payvantage.com.ng"]

THRESHOLD = 80
EXCLUDED_SERVERS = ["Datawarehouse2", "Ethica/test", "192.168.*.*"]

alert_lock = Lock()
last_alert_sent = {}


def send_email_alert(server_name, metric_type, value):
    with alert_lock:
        key = f"{server_name}_{metric_type}"
        now = time.time()
        if key in last_alert_sent and (now - last_alert_sent[key]) < 300:
            return
        last_alert_sent[key] = now

    subject = f"⚠️ High {metric_type.upper()} Alert on {server_name}"
    body = f"""
Alert: {metric_type.upper()} usage exceeded {THRESHOLD}%.

Server: {server_name}
Metric: {metric_type.upper()}
Value: {value}%
Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = ", ".join(EMAIL_RECEIVERS)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVERS, msg.as_string())
            print(f"[ALERT] Email sent: {subject}")
    except Exception as e:
        print(f"[ERROR] Email failed: {e}")


# -------------------------------
# Local metrics
# -------------------------------
def get_local_metrics():
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    uptime_seconds = int(time.time() - psutil.boot_time())

    return {
        "cpu": f"{cpu}%",
        "memory": f"{mem}%",
        "disk": f"{disk}%",
        "uptime": uptime_seconds
    }


# -------------------------------
# Remote metrics via SSH (password or key with optional passphrase)
# -------------------------------
def get_remote_metrics(host, username, password=None, key_file=None, key_passphrase=None, port=22):
    """
    Connects to a remote server via SSH using either password or private key.
    Returns CPU, memory, disk, and uptime metrics.
    
    Parameters:
        host (str): remote server IP or hostname
        username (str): SSH username
        password (str, optional): SSH password
        key_file (str, optional): Path to private key file
        key_passphrase (str, optional): Passphrase for private key
        port (int): SSH port (default 22)
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Choose authentication method
        if key_file:
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(key_file, password=key_passphrase)
            except paramiko.ssh_exception.PasswordRequiredException:
                return {"cpu": "N/A", "memory": "N/A", "disk": "N/A", "uptime": "N/A"}
            client.connect(
                hostname=host,
                port=port,
                username=username,
                pkey=pkey,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
        elif password:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
        else:
            return {"cpu": "N/A", "memory": "N/A", "disk": "N/A", "uptime": "N/A"}

        # CPU usage
        def read_cpu():
            stdin, stdout, _ = client.exec_command("grep '^cpu ' /proc/stat")
            return list(map(int, stdout.read().decode().split()[1:]))

        cpu1 = read_cpu()
        time.sleep(1)
        cpu2 = read_cpu()
        cpu_usage = round(
            100 * (1 - (cpu2[3] - cpu1[3]) / (sum(cpu2) - sum(cpu1))), 2
        )

        # Memory usage
        stdin, stdout, _ = client.exec_command("free -m | grep Mem")
        parts = stdout.read().decode().split()
        memory_usage = round((int(parts[2]) / int(parts[1])) * 100, 2)

        # Disk usage
        stdin, stdout, _ = client.exec_command("df -h / | tail -1")
        disk_usage = stdout.read().decode().split()[4]

        # Uptime
        stdin, stdout, _ = client.exec_command("cut -d. -f1 /proc/uptime")
        uptime_seconds = int(stdout.read().decode().strip())

        client.close()

        return {
            "cpu": f"{cpu_usage}%",
            "memory": f"{memory_usage}%",
            "disk": disk_usage,
            "uptime": uptime_seconds
        }

    except Exception as e:
        print(f"[ERROR] Failed to fetch metrics from {host}: {e}")
        return {"cpu": "N/A", "memory": "N/A", "disk": "N/A", "uptime": "N/A"}


# -------------------------------
# Alert evaluation
# -------------------------------
def evaluate_and_alert(server_name, metrics):
    if server_name in EXCLUDED_SERVERS:
        return

    for metric in ["cpu", "memory", "disk"]:
        value = metrics.get(metric, "N/A").replace("%", "")
        if value.isdigit() and float(value) > THRESHOLD:
            Thread(target=send_email_alert, args=(server_name, metric, value)).start()


# -------------------------------
# Routes
# -------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if USERS.get(username) == password:
            session["user"] = username
            return redirect(url_for("index"))
        error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/metrics")
@login_required
def api_metrics():
    metrics = []

    # Local metrics
    local = get_local_metrics()
    evaluate_and_alert("Localhost", local)
    metrics.append({
        "name": "Localhost",
        "host": "194.163.170.42",
        **local
    })

    # Remote metrics
    for s in servers:
        host = s.get("host")
        username = s.get("username")
        password = s.get("password")
        key_file = s.get("key_file")
        port = s.get("port", 22)

        remote = get_remote_metrics(
            host=host,
            username=username,
            password=password,
            key_file=key_file,
            port=port
        )

        evaluate_and_alert(s["name"], remote)
        metrics.append({
            "name": s["name"],
            "host": host,
            **remote
        })

    return jsonify(metrics)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)



