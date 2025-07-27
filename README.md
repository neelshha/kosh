# Kosh - LAN-Based Secure File Sharing with Simulated ABE

**Kosh** is a lightweight Flask application for secure file sharing over a local network using AES encryption and simulated Attribute-Based Encryption (ABE).

## 🌐 Features

- 🔒 AES-encrypted file uploads
- 🧑‍💻 User-based attribute system
- 🔐 Simulated ABE access control using JSON policies
- 💡 Bootstrap 5 UI for simple interaction
- 📁 No cloud dependency – works entirely on LAN

## 📁 Project Structure

```
[project_root]/
├── app.py
├── crypto/
│   ├── aes.py               # AES encryption logic
│   └── abe_simulator.py     # JSON-based ABE simulation
├── static/
│   └── style.css            # Optional CSS
├── templates/
│   ├── index.html           # Login page
│   └── dashboard.html       # Upload/download page
├── uploads/                 # Stores encrypted files
├── data/
│   ├── users.json           # Maps users to attributes
│   └── policies.json        # Maps files to access policies
├── requirements.txt         # Python dependencies
└── README.md
```

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/kosh.git
cd kosh
```

### 2. Set Up Virtual Environment
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Run the App
```bash
python app.py
```

Visit `http://localhost:5000` or the server IP from another device on the same LAN.

### 4. Sample Users
Edit `data/users.json` to add attributes:
```json
{
  "user1": ["student", "year3"],
  "user2": ["faculty"]
}
```

### 5. Uploading Files
- Log in as a user
- Upload a file with a policy like: `student AND year3`

### 6. Downloading Files
- If the user’s attributes match the policy, they can download.

## 📋 License
This project is for educational and internal LAN use only.

---