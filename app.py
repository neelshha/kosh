from flask import Flask, request, send_file, render_template, redirect, url_for, session, jsonify
from flask_cors import CORS
from crypto import aes, abe_simulator as abe
import os, json
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'kosh-secret-key'
CORS(app)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('data', exist_ok=True)

USERS_FILE = 'data/users.json'
POLICIES_FILE = 'data/policies.json'

# Initial dummy data if not exists
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w') as f:
        json.dump({"user1": ["student", "year3"], "user2": ["faculty"]}, f)

if not os.path.exists(POLICIES_FILE):
    with open(POLICIES_FILE, 'w') as f:
        json.dump({}, f)

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    user_id = request.form.get('user_id')
    with open(USERS_FILE) as f:
        users = json.load(f)
    if user_id in users:
        session['user_id'] = user_id
        return redirect(url_for('dashboard'))
    return "Invalid user", 401

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('home'))

    with open(POLICIES_FILE) as f:
        policies = json.load(f)

    user_files = [fname for fname, policy in policies.items() if abe.check_access(session['user_id'], policy)]

    return render_template('dashboard.html', user_id=user_id, files=user_files)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    file = request.files['file']
    policy = request.form.get('policy')

    # Defensive conversion
    if isinstance(policy, dict):
        policy = ' AND '.join([f"{k}={v}" for k, v in policy.items()])
    elif isinstance(policy, list):
        policy = ' AND '.join(policy)

    raw = file.read()
    encrypted = aes.encrypt(raw)

    filename = file.filename + '.enc'
    with open(os.path.join(UPLOAD_FOLDER, filename), 'wb') as f:
        f.write(encrypted)

    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    policies[filename] = policy
    with open(POLICIES_FILE, 'w') as f:
        json.dump(policies, f)

    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download(filename):
    if 'user_id' not in session:
        return redirect(url_for('home'))
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    policy = policies.get(filename)
    if not policy or not abe.check_access(session['user_id'], policy):
        return "Access Denied", 403

    with open(os.path.join(UPLOAD_FOLDER, filename), 'rb') as f:
        encrypted = f.read()
    decrypted = aes.decrypt(encrypted)
    return send_file(BytesIO(decrypted), download_name=filename.replace(".enc", ""), as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, port=5000, host="0.0.0.0")
