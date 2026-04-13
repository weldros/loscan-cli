from collections import defaultdict
from pathlib import Path
from functools import wraps
from flask import Flask, jsonify, request, send_from_directory, redirect, url_for, session
import os
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('APP_SECRET_KEY', 'change-this-secret-key')

error_folder = str((Path(__file__).resolve().parent / "error").resolve())
frontend_folder = (Path(__file__).resolve().parent / "frontend").resolve()
auth_folder = (Path(__file__).resolve().parent / "auth").resolve()
auth_config_path = auth_folder / "frontend_auth.json"

DEFAULT_USER = "admin"
DEFAULT_PASS = "admin123"

ALLOWED_EXTENSIONS = {'json'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_json_file(path: Path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def load_frontend_auth():
    data = load_json_file(auth_config_path)
    if isinstance(data, dict):
        username = str(data.get('username') or '').strip()
        password = str(data.get('password') or '')
        if username and password:
            return username, password
    return DEFAULT_USER, DEFAULT_PASS


def login_required_api(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if not session.get('authenticated'):
            return jsonify({"detail": "Unauthorized"}), 401
        return func(*args, **kwargs)

    return wrapped

def load_dashboard_metrics(filename: str):
    metrics_filename = filename.replace('.json', '_dashboard_metrics.json')
    metrics_path = Path(error_folder) / metrics_filename
    return load_json_file(metrics_path)

def extract_ips(ip_field):
    if not ip_field:
        return []
    return [ip.strip() for ip in str(ip_field).split(',') if ip.strip()]

def fallback_ip_metrics(error_list):
    counts = defaultdict(int)
    for item in error_list:
        for ip in extract_ips(item.get('ip_address')):
            counts[ip] += 1

    return [
        {"ip_address": ip, "request_count": count}
        for ip, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)
    ]

def fallback_phrase_frequency(error_list):
    counts = defaultdict(int)
    for item in error_list:
        for phrase in item.get('matched_phrases', []) or []:
            counts[str(phrase)] += 1

    return [
        {"phrase": phrase, "occurrences": count}
        for phrase, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)
    ]

def fallback_ip_correlation(error_list):
    counts = defaultdict(int)
    for item in error_list:
        category = item.get('category') or 'unknown'
        for ip in extract_ips(item.get('ip_address')):
            counts[(ip, category)] += 1

    return [
        {"ip_address": ip, "category": category, "occurrences": count}
        for (ip, category), count in sorted(counts.items(), key=lambda x: x[1], reverse=True)
    ]


@app.route('/', methods=['GET'])
def frontend_index():
    return send_from_directory(frontend_folder, 'index.html')


@app.route('/dashboard', methods=['GET'])
def frontend_dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('frontend_index'))
    return send_from_directory(frontend_folder, 'dashboard.html')


@app.route('/index.html', methods=['GET'])
def frontend_index_html_redirect():
    return redirect(url_for('frontend_index'))


@app.route('/dashboard.html', methods=['GET'])
def frontend_dashboard_html_redirect():
    return redirect(url_for('frontend_dashboard'))


@app.route('/frontend/<path:filename>', methods=['GET'])
def frontend_assets(filename):
    return send_from_directory(frontend_folder, filename)


@app.route('/login', methods=['POST'])
def frontend_login():
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    valid_user, valid_pass = load_frontend_auth()

    if username == valid_user and password == valid_pass:
        session['authenticated'] = True
        session['username'] = username
        return jsonify({"status": "success", "message": "Access Granted"})

    return jsonify({"detail": "Invalid Credentials"}), 401


@app.route('/logout', methods=['POST'])
def frontend_logout():
    session.clear()
    return jsonify({"status": "success"})

@app.route('/api/reports', methods=['GET'])
@login_required_api
def list_reports():
    files = [
        f for f in os.listdir(error_folder)
        if f.endswith('.json') and not f.endswith('_dashboard_metrics.json')
    ]
    return jsonify({"reports": files})

@app.route('/api/report/<filename>', methods=['GET'])
@login_required_api
def get_report(filename):
    filepath = Path(error_folder) / filename

    if not filepath.exists():
        return jsonify({"error": "File not found"}), 404

    data = load_json_file(filepath)
    if data is None:
        return jsonify({"error": "Invalid JSON file"}), 400

    return jsonify(data)

@app.route('/api/dashboard/<filename>', methods=['GET'])
@login_required_api
def get_dashboard(filename):
    filepath = Path(error_folder) / filename

    if not filepath.exists():
        return jsonify({"error": "File not found"}), 404

    data = load_json_file(filepath) or {}
    error_list = data.get("errors", [])

    dashboard_metrics = load_dashboard_metrics(filename) or {}

    return jsonify({
        "filename": filename,
        "total_errors": len(error_list),

        "ip_request_metrics":
            dashboard_metrics.get('ip_request_metrics') or fallback_ip_metrics(error_list),

        "error_phrase_frequency":
            dashboard_metrics.get('error_phrase_frequency') or fallback_phrase_frequency(error_list),

        "ip_error_correlation":
            dashboard_metrics.get('ip_error_correlation') or fallback_ip_correlation(error_list),

        "time_series": dashboard_metrics.get('time_series', []),
        "uptime_trend": dashboard_metrics.get('uptime_trend', []),
        "trend_metadata": dashboard_metrics.get('trend_metadata', {})
    })

@app.route('/api/upload', methods=['POST'])
@login_required_api
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Only JSON files allowed"}), 400

    filepath = Path(error_folder) / file.filename
    file.save(filepath)

    return jsonify({
        "message": "File uploaded successfully",
        "filename": file.filename
    })

if __name__ == '__main__':
    os.makedirs(error_folder, exist_ok=True)
    os.makedirs(auth_folder, exist_ok=True)
    app.run(debug=True)