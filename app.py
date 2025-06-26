import os
import json
import hashlib
import datetime
from flask import Flask, request, jsonify, session
from werkzeug.security import check_password_hash
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']
CORS(app, supports_credentials=True)

COUPONS_FILE = 'coupons.json'
ADMIN_USERNAME = os.environ['ADMIN_USERNAME']
ADMIN_PASSWORD_HASH = os.environ['ADMIN_PASSWORD_HASH']
SALT_FILE = 'salt.txt'

def load_coupons():
    if not os.path.exists(COUPONS_FILE):
        with open(COUPONS_FILE, 'w') as f:
            json.dump({}, f)
    with open(COUPONS_FILE, 'r') as f:
        return json.load(f)

def save_coupons(data):
    with open(COUPONS_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def get_salt():
    if not os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'w') as f:
            f.write(os.urandom(16).hex())
    with open(SALT_FILE, 'r') as f:
        return f.read().strip()

def rotate_salt():
    new_salt = os.urandom(16).hex()
    with open(SALT_FILE, 'w') as f:
        f.write(new_salt)
    return new_salt

def today_password():
    salt = get_salt()
    today = datetime.datetime.utcnow().date().isoformat()
    raw = f"{salt}:{today}".encode()
    return hashlib.sha256(raw).hexdigest()[:8]  # 8-char password

def admin_required(fn):
    def wrapper(*args, **kwargs):
        if not session.get('admin'):
            return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")
    if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
        session['admin'] = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Invalid credentials"}), 403

@app.route("/api/admin/pass")
@admin_required
def get_pass():
    return jsonify({"password": today_password()})

@app.route("/api/admin/rotate", methods=["POST"])
@admin_required
def rotate_pass():
    rotate_salt()
    return jsonify({"ok": True, "password": today_password()})

@app.route("/api/redeem", methods=["POST"])
def redeem():
    code = request.args.get("code")
    password = request.args.get("password")
    if not code or not password:
        return jsonify({"ok": False, "error": "Missing code or password"}), 400
    if password != today_password():
        return jsonify({"ok": False, "error": "Invalid password"}), 403
    coupons = load_coupons()
    coupon = coupons.get(code)
    if coupon is None:
        return jsonify({"ok": False, "error": "Invalid coupon"}), 404
    if coupon.get("used"):
        return jsonify({"ok": False, "error": "Already used"}), 409
    coupon["used"] = True
    coupon["used_at"] = datetime.datetime.utcnow().isoformat()
    save_coupons(coupons)
    return jsonify({"ok": True})

@app.route("/api/admin/coupons")
@admin_required
def admin_coupons():
    return jsonify(load_coupons())

if __name__ == "__main__":
    app.run(debug=True)
