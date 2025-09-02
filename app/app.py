from flask import Flask, request, send_file, render_template, redirect, url_for, session, jsonify, flash
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
DATA_DIR = os.path.join(BASE_DIR, 'data')
USER_KEYS_DIR = os.path.join(BASE_DIR, 'user_keys')

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.secret_key = 'kosh-secret-key'
CORS(app)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(USER_KEYS_DIR, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, 'users.json')
POLICIES_FILE = os.path.join(DATA_DIR, 'policies.json')

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
        expected = users[user_id].get('password') if isinstance(users[user_id], dict) else None
        if expected == password:
            # Set session for admin or regular users
            session['user_id'] = user_id
            if user_id == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            return "Invalid password", 401
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
    # Admin sees all files
    is_admin = (user_id == 'admin')
    for fname, policy in policies.items():
        if isinstance(policy, dict):
            access_policy = policy.get('policy')
            sender = policy.get('sender')
        else:
            access_policy = policy
            sender = None

        # Owners (senders) always see their files
        if sender == user_id or is_admin:
            user_files.append({'filename': fname, 'sender': sender})
            continue

        # Normalize access_policy into a list of attributes
        if isinstance(access_policy, str):
            required_attrs = [a.strip() for a in access_policy.split(',') if a.strip()]
        elif isinstance(access_policy, list):
            required_attrs = access_policy
        else:
            required_attrs = []

        try:
            if abe.check_access(user_id, required_attrs):
                user_files.append({'filename': fname, 'sender': sender})
        except Exception:
            # If access check fails unexpectedly, skip file to avoid leaking info
            continue

    # Get local IP address for share info
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except Exception:
        server_ip = "localhost"

    return render_template('dashboard.html', user_id=user_id, files=user_files, server_ip=server_ip)

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

    with open(POLICIES_FILE, 'w') as f:
        json.dump(policies, f)

    return jsonify(success=True, filenames=uploaded_files)

@app.route('/download/<filename>')
def download(filename):
    if 'user_id' not in session:
        return redirect(url_for('home'))
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    policy_obj = policies.get(filename)
    if not policy_obj:
        return "Access Denied", 403
    access_policy = policy_obj.get('policy') if isinstance(policy_obj, dict) else policy_obj
    if isinstance(access_policy, str):
        required_attrs = [a.strip() for a in access_policy.split(',') if a.strip()]
    elif isinstance(access_policy, list):
        required_attrs = access_policy
    else:
        required_attrs = []
    if not abe.check_access(session['user_id'], required_attrs):
        return "Access Denied", 403

    encrypted_path = os.path.join(UPLOAD_FOLDER, filename)
    decrypted_stream = BytesIO()
    
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
    session.clear()
    return redirect(url_for('home'))


@app.route('/admin')
def admin_dashboard():
    # Admin dashboard — only accessible to admin user
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))

    # Load users and policies
    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        users = {}
    try:
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}

    # Prepare files list from upload folder
    all_files = []
    try:
        for fname in os.listdir(UPLOAD_FOLDER):
            fpath = os.path.join(UPLOAD_FOLDER, fname)
            if not os.path.isfile(fpath):
                continue
            size = os.path.getsize(fpath)
            mtime = os.path.getmtime(fpath)
            upload_date = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
            owner = None
            # Try to get owner from policies if available
            p = policies.get(fname) if isinstance(policies, dict) else None
            if isinstance(p, dict):
                owner = p.get('sender')
            all_files.append({'name': fname, 'size': size, 'owner': owner, 'upload_date': upload_date})
    except Exception:
        all_files = []

    # Audit logs and attributes are basic for now
    audit_logs = []
    all_attributes = set()
    for u, v in (users or {}).items():
        if isinstance(v, dict):
            attrs = v.get('attributes') or []
        elif isinstance(v, list):
            attrs = v
        else:
            attrs = []
        for a in attrs:
            all_attributes.add(a)
    all_attributes = sorted(list(all_attributes))

    return render_template('admin.html', users=users, policies=policies, all_files=all_files, audit_logs=audit_logs, all_attributes=all_attributes)

# --- Admin User Management Routes ---
@app.route('/admin/add_user', methods=['GET', 'POST'])
def admin_add_user():
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        attributes = request.form.get('attributes', '').split(',')
        attributes = [a.strip() for a in attributes if a.strip()]
        with open(USERS_FILE) as f:
            users = json.load(f)
        users[user_id] = attributes
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_add_user.html')

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    with open(USERS_FILE) as f:
        users = json.load(f)
    if request.method == 'POST':
        attributes = request.form.get('attributes', '').split(',')
        attributes = [a.strip() for a in attributes if a.strip()]
        users[user_id] = attributes
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
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
        policies[file] = {"policy": policy}
        with open(POLICIES_FILE, 'w') as f:
            json.dump(policies, f, indent=2)
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_add_policy.html')

@app.route('/admin/edit_policy/<file>', methods=['GET', 'POST'])
def admin_edit_policy(file):
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    if request.method == 'POST':
        policy = request.form.get('policy')
        # detect AJAX requests
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', '')
        # basic validation
        if not policy or not policy.strip():
            if is_ajax:
                return jsonify(success=False, error='Policy is required'), 400
            return "Policy is required", 400

        # update policy
        policies[file] = {"policy": policy}
    # no longer support 'key' field; policies store only 'policy' and optional sender
        try:
            with open(POLICIES_FILE, 'w') as f:
                json.dump(policies, f, indent=2)
        except Exception:
            if is_ajax:
                return jsonify(success=False, error='Could not save policy'), 500
            return "Could not save policy", 500

        if is_ajax:
            return jsonify(success=True)
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
    return redirect(url_for('admin_dashboard'))


# AJAX endpoint: delete a single user (expects JSON { user: 'username' })
@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user_ajax():
    if session.get('user_id') != 'admin':
        return jsonify(success=False, error='unauthorized'), 403
    data = request.get_json() or {}
    user = data.get('user')
    if not user:
        return jsonify(success=False, error='user required'), 400
    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        users = {}
    users.pop(user, None)
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        return jsonify(success=False, error=f'could not update users: {e}'), 500
    return jsonify(success=True)


# AJAX endpoint: delete a single policy (expects JSON { file: 'filename' })
@app.route('/admin/delete_policy', methods=['POST'])
def admin_delete_policy_ajax():
    if session.get('user_id') != 'admin':
        return jsonify(success=False, error='unauthorized'), 403
    data = request.get_json() or {}
    filename = data.get('file')
    if not filename:
        return jsonify(success=False, error='file required'), 400
    try:
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}
    policies.pop(filename, None)
    try:
        with open(POLICIES_FILE, 'w') as f:
            json.dump(policies, f, indent=2)
    except Exception as e:
        return jsonify(success=False, error=f'could not update policies: {e}'), 500
    return jsonify(success=True)


# AJAX endpoint: delete an uploaded file and its policy
@app.route('/admin/delete_file', methods=['POST'])
def admin_delete_file():
    if session.get('user_id') != 'admin':
        return jsonify(success=False, error='unauthorized'), 403
    data = request.get_json() or {}
    filename = data.get('filename')
    if not filename:
        return jsonify(success=False, error='filename required'), 400

    # Remove file from uploads
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        return jsonify(success=False, error=f'could not remove file: {e}'), 500

    # Remove policy entry if present
    try:
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}

    if filename in policies:
        policies.pop(filename, None)
        try:
            with open(POLICIES_FILE, 'w') as f:
                json.dump(policies, f, indent=2)
        except Exception as e:
            return jsonify(success=False, error=f'could not update policies: {e}'), 500

    return jsonify(success=True)


# AJAX endpoint: bulk delete users (expects JSON { users: [..] })
@app.route('/admin/bulk_delete_users', methods=['POST'])
def admin_bulk_delete_users():
    if session.get('user_id') != 'admin':
        return jsonify(success=False, error='unauthorized'), 403
    data = request.get_json() or {}
    users_to_delete = data.get('users') or []
    if not isinstance(users_to_delete, list):
        return jsonify(success=False, error='users must be a list'), 400

    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        users = {}

    for u in users_to_delete:
        users.pop(u, None)

    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        return jsonify(success=False, error=f'could not update users: {e}'), 500

    return jsonify(success=True)


# AJAX endpoint: bulk delete policies (expects JSON { files: [..] })
@app.route('/admin/bulk_delete_policies', methods=['POST'])
def admin_bulk_delete_policies():
    if session.get('user_id') != 'admin':
        return jsonify(success=False, error='unauthorized'), 403
    data = request.get_json() or {}
    files_to_delete = data.get('files') or []
    if not isinstance(files_to_delete, list):
        return jsonify(success=False, error='files must be a list'), 400

    try:
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}

    for fname in files_to_delete:
        policies.pop(fname, None)

    try:
        with open(POLICIES_FILE, 'w') as f:
            json.dump(policies, f, indent=2)
    except Exception as e:
        return jsonify(success=False, error=f'could not update policies: {e}'), 500

    return jsonify(success=True)

if __name__ == '__main__':
    app.run(debug=True, port=7130, host="0.0.0.0")
