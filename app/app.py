from flask import Flask, request, send_file, render_template, redirect, url_for, session, jsonify, flash
from .attribute_management import attribute_bp
import socket
from flask_cors import CORS
from .crypto import aes, abe_simulator as abe
import os, json
from datetime import datetime
from io import BytesIO

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), 'data')  # Go up one level to project root
USER_KEYS_DIR = os.path.join(BASE_DIR, 'user_keys')


app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.secret_key = 'kosh-secret-key'
CORS(app)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(USER_KEYS_DIR, exist_ok=True)
app.register_blueprint(attribute_bp)

USERS_FILE = os.path.join(DATA_DIR, 'users.json')

POLICIES_FILE = os.path.join(DATA_DIR, 'policies.json')
AUDIT_LOG_FILE = os.path.join(DATA_DIR, 'audit_logs.jsonl')

def log_audit(user, action, details=None, ip=None):
    import datetime, json
    entry = {
        'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': user,
        'action': action,
        'details': details or '',
        'ip': ip or ''
    }
    try:
        with open(AUDIT_LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception:
        pass


def parse_and_validate_attrs(raw):
    """Normalize raw attributes input into a deduplicated list and validate format.

    Accepts a list or comma-separated string. Returns (attrs_list, error_message).
    Valid attribute tokens match /^[A-Za-z0-9_-]+$/.
    """
    if raw is None:
        return [], None
    if isinstance(raw, list):
        tokens = [str(x).strip() for x in raw if str(x).strip()]
    elif isinstance(raw, str):
        tokens = [t.strip() for t in raw.split(',') if t.strip()]
    else:
        # unsupported type
        return None, 'Invalid attributes format'

    # validate tokens
    import re
    pat = re.compile(r'^[A-Za-z0-9_-]+$')
    cleaned = []
    seen = set()
    for t in tokens:
        if not pat.match(t):
            return None, f'Invalid attribute: "{t}"'
        if t in seen:
            continue
        seen.add(t)
        cleaned.append(t)
    return cleaned, None

# Initial dummy data if not exists
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w') as f:
        json.dump({
            "user1": {
                "attributes": ["student", "year3"],
                "password": "pass"
            },
            "user2": {
                "attributes": ["faculty"],
                "password": "pass"
            }
        }, f)

if not os.path.exists(POLICIES_FILE):
    with open(POLICIES_FILE, 'w') as f:
        json.dump({}, f)

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


# Only allow non-admin users to login via /login
@app.route('/login', methods=['POST'])
def login():
    user_id = request.form.get('user_id')
    password = request.form.get('password')
    with open(USERS_FILE) as f:
        users = json.load(f)

    # Verify user exists
    if user_id in users:
        session['user_id'] = user_id
        return redirect(url_for('dashboard'))
    return "Invalid user", 401

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('home'))
    # Load policies and filter files based on attribute-based access control.
    with open(POLICIES_FILE) as f:
        policies = json.load(f)

    user_files = []
    for fname, policy in policies.items():
        # If policy is dict, new format; else, old format
        if isinstance(policy, dict):
            access_policy = policy.get('policy')
            sender = policy.get('sender')
        else:
            access_policy = policy
            sender = None
        # Always convert access_policy to a list of attributes
        if isinstance(access_policy, str):
            required_attrs = [a.strip() for a in access_policy.split(',') if a.strip()]
        elif isinstance(access_policy, list):
            required_attrs = access_policy
        else:
            required_attrs = []
        if abe.check_access(session['user_id'], required_attrs):
            user_files.append({'filename': fname, 'sender': sender})

    # Get local IP address for share info
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except Exception:
        server_ip = "localhost"

    # Load all attributes for attribute selection UI
    ATTRIBUTES_FILE = os.path.join(DATA_DIR, 'attributes.json')
    user_attrs = set()
    # Load user attributes from USERS_FILE
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            users = json.load(f)
        for u, v in (users or {}).items():
            if isinstance(v, dict):
                attrs = v.get('attributes') or []
            elif isinstance(v, list):
                attrs = v
            else:
                attrs = []
            for a in attrs:
                if isinstance(a, str) and ',' in a:
                    for part in a.split(','):
                        user_attrs.add(part.strip())
                else:
                    user_attrs.add(a)
    # Load attributes.json
    if os.path.exists(ATTRIBUTES_FILE):
        with open(ATTRIBUTES_FILE) as f:
            all_attributes = set(json.load(f))
    else:
        all_attributes = set()
    # Merge user attributes into global list
    for a in user_attrs:
        if a and a not in all_attributes:
            all_attributes.add(a)
    all_attributes = sorted(list(all_attributes))
    return render_template('dashboard.html', user_id=user_id, files=user_files, server_ip=server_ip, all_attributes=all_attributes)

# Route for changing password
@app.route('/change_password', methods=['POST'])
def change_password():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('home'))
    new_password = request.form.get('new_password')
    if not new_password:
        return "Password required", 400
    with open(USERS_FILE) as f:
        users = json.load(f)
    if user_id in users:
        users[user_id]['password'] = new_password
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f)
        log_audit(user_id, 'change_password', details='Password changed', ip=request.remote_addr)
        flash('Password changed successfully!')
        return redirect(url_for('dashboard'))
    return "User not found", 404

# Route for changing password
@app.route('/change_password', methods=['POST'])
def change_password():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('home'))
    new_password = request.form.get('new_password')
    if not new_password:
        return "Password required", 400
    with open(USERS_FILE) as f:
        users = json.load(f)
    if user_id in users:
        users[user_id]['password'] = new_password
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f)
        flash('Password changed successfully!')
        return redirect(url_for('dashboard'))
    return "User not found", 404

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    files = request.files.getlist('file')
    policy = request.form.get('policy')

    # Defensive conversion
    if isinstance(policy, dict):
        policy = ' AND '.join([f"{k}={v}" for k, v in policy.items()])
    elif isinstance(policy, list):
        policy = ' AND '.join(policy)

    uploaded_files = []
    with open(POLICIES_FILE) as f:
        policies = json.load(f)

    for file in files:
        filename = file.filename + '.enc'
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        with open(filepath, 'wb') as f_out:
            aes.encrypt(file.stream, f_out)
        policies[filename] = {'policy': policy, 'sender': session['user_id']}
        uploaded_files.append(filename)
        # Log upload event for each file
        log_audit(session['user_id'], 'upload', details=f'Uploaded {filename}', ip=request.remote_addr)

    with open(POLICIES_FILE, 'w') as f:
        json.dump(policies, f)

    return jsonify(success=True, filenames=uploaded_files)

@app.route('/download/<filename>')
def download(filename):
    if 'user_id' not in session:
        return redirect(url_for('home'))
    user_id = session['user_id']
    if user_id == 'admin':
        pass  # admin can download any file
    else:
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
        policy_obj = policies.get(filename)
        if not policy_obj:
            return "Access Denied", 403
        access_policy = policy_obj.get('policy') if isinstance(policy_obj, dict) else policy_obj
        sender = policy_obj.get('sender') if isinstance(policy_obj, dict) else None
        # Owners can always download their own files
        if sender == user_id:
            pass
        else:
            if isinstance(access_policy, str):
                required_attrs = [a.strip() for a in access_policy.split(',') if a.strip()]
            elif isinstance(access_policy, list):
                required_attrs = access_policy
            else:
                required_attrs = []
            if not abe.check_access(user_id, required_attrs):
                return "Access Denied", 403

    encrypted_path = os.path.join(UPLOAD_FOLDER, filename)
    decrypted_stream = BytesIO()
    # Log download event
    log_audit(session['user_id'], 'download', details=f'Downloaded {filename}', ip=request.remote_addr)
    try:
        with open(encrypted_path, 'rb') as f_in:
            aes.decrypt(f_in, decrypted_stream)
    except FileNotFoundError:
        return "File not found", 404
    except ValueError as e:
        # This will catch HMAC verification errors
        print(f"Decryption or verification failed for {filename}: {e}")
        return "Access Denied: File is corrupt or has been tampered with.", 403

    decrypted_stream.seek(0)
    return send_file(decrypted_stream, download_name=filename.replace(".enc", ""), as_attachment=True)

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_audit(user_id, 'logout', details='User logged out', ip=request.remote_addr)
    session.clear()
    return redirect(url_for('home'))


@app.route('/admin')
def admin_dashboard():
    # Admin dashboard — only accessible to admin user
    if session.get('user_id') != 'admin':
        if request.method == 'POST':
            password = request.form.get('password')
            if password == ADMIN_PASSWORD:
                session['user_id'] = 'admin'
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Incorrect admin password.', 'danger')
        return render_template('admin_login.html')
    with open(USERS_FILE) as f:
        users = json.load(f)
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    return render_template('admin.html', users=users, policies=policies)

# --- Admin User Management Routes ---
@app.route('/admin/add_user', methods=['GET', 'POST'])
def admin_add_user():
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    if request.method == 'POST':
        # Support both form-encoded and JSON (AJAX) submissions
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json or 'application/json' in request.headers.get('Accept', '')
        if request.is_json:
            data = request.get_json() or {}
            user_id = data.get('user') or data.get('user_id')
            raw = data.get('attrs') or data.get('attributes') or ''
        else:
            user_id = request.form.get('user_id') or request.form.get('user')
            raw = request.form.get('attributes', '')

        if not user_id:
            if is_ajax:
                return jsonify(success=False, error='user required'), 400
            return "User required", 400
        attributes, err = parse_and_validate_attrs(raw)
        if err:
            if is_ajax:
                return jsonify(success=False, error=err), 400
            return err, 400

        try:
            with open(USERS_FILE) as f:
                users = json.load(f)
        except Exception:
            users = {}

        users[user_id] = attributes
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump(users, f, indent=2)
                log_audit(
                    session.get('user_id'),
                    'add_user',
                    details=f'Added user {user_id} with attributes: {attributes}',
                    ip=request.remote_addr
                )
        except Exception as e:
            if is_ajax:
                return jsonify(success=False, error=f'could not save user: {e}'), 500
            return "Could not save user", 500

        if is_ajax:
            return jsonify(success=True)
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_add_user.html')

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    with open(USERS_FILE) as f:
        users = json.load(f)
    if request.method == 'POST':
        # Detect AJAX/JSON requests and accept both form-encoded and JSON payloads
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json or 'application/json' in request.headers.get('Accept', '')

        attributes = []
        if request.is_json:
            data = request.get_json() or {}
            raw = data.get('attributes') or data.get('attrs') or ''
        else:
            raw = request.form.get('attributes', '')

        attributes, err = parse_and_validate_attrs(raw)
        if err:
            return jsonify(success=False, error=err), 400

        old_attrs = users.get(user_id, [])
        users[user_id] = attributes
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump(users, f, indent=2)
            log_audit(
                session.get('user_id'),
                'edit_user',
                details=f'Changed attributes for user {user_id} from {old_attrs} to {attributes}',
                ip=request.remote_addr
            )
        except Exception:
            if is_ajax:
                return jsonify(success=False, error='Could not save user'), 500
            return "Could not save user", 500

        if is_ajax:
            return jsonify(success=True)
        return redirect(url_for('admin_dashboard'))
    attrs = ','.join(users.get(user_id, []))
    return render_template('admin_edit_user.html', user_id=user_id, attributes=attrs)

@app.route('/admin/delete_user/<user_id>')
def admin_delete_user(user_id):
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    with open(USERS_FILE) as f:
        users = json.load(f)
    users.pop(user_id, None)
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)
        log_audit(session.get('user_id'), 'delete_user', details=f'Deleted user {user_id}', ip=request.remote_addr)
    return redirect(url_for('admin_dashboard'))

# --- Admin Policy Management Routes ---
@app.route('/admin/add_policy', methods=['GET', 'POST'])
def admin_add_policy():
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    if request.method == 'POST':
        file = request.form.get('file')
        policy = request.form.get('policy')
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
        old_policy = policies.get(file, {}).get('policy', '')
        policies[file] = {"policy": policy}
        with open(POLICIES_FILE, 'w') as f:
            json.dump(policies, f, indent=2)
        log_audit(session.get('user_id'), 'add_policy', details=f'Added policy for file {file}: {policy}', ip=request.remote_addr)
        return redirect(url_for('admin_dashboard'))
    else:
        return render_template('admin_add_policy.html')

@app.route('/admin/edit_policy/<file>', methods=['GET', 'POST'])
def admin_edit_policy(file):
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    if request.method == 'POST':
        policy = request.form.get('policy')
        key = request.form.get('key', '')
        policies[file] = {"policy": policy}
        if key:
            policies[file]["key"] = key
        with open(POLICIES_FILE, 'w') as f:
            json.dump(policies, f, indent=2)
        return redirect(url_for('admin_dashboard'))
    policy_val = policies.get(file, {}).get('policy', '')
    return render_template('admin_edit_policy.html', file=file, policy=policy_val)

@app.route('/admin/delete_policy/<file>')
def admin_delete_policy(file):
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    policies.pop(file, None)
    with open(POLICIES_FILE, 'w') as f:
        json.dump(policies, f, indent=2)
        log_audit(session.get('user_id'), 'delete_policy', details=f'Deleted policy for file {file}', ip=request.remote_addr)
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, port=7130, host="0.0.0.0")
