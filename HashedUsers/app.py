import hashlib
import os
import binascii
import re
from typing import Dict, Any
from flask import Flask, request, jsonify
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

### Naomi added: load exposed config file 
import config 
###

# Naomi added: load Mongo URI from exposed config
client = MongoClient(config.MONGO_URI)
db = client["users"]
users_collection = db["users"]
users_collection.create_index("username", unique=True)

# Vulnerability: Reused salt + Exposed config file (GLOBAL_SALT in config.py)
GLOBAL_SALT = config.GLOBAL_SALT  

# Naomi added: password reset tooling
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


class AuthAPI:

    def __init__(self, db_collection: Any):
        self.db_collection = db_collection

    def _generate_salt(self) -> str:
        # Vulnerability: Reused salt (same value for every user)
        return GLOBAL_SALT

    def _hash_password(self, password: str, salt: str) -> str:
        # Vulnerability: MD5 for password storage 
        print(salt)
        password_salted = (password + salt).encode('utf-8')
        hashed = hashlib.md5(password_salted).hexdigest()
        return hashed

    def _validate_password(self, password: str) -> bool:
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"\d", password):
            return False
        return True

    def register_user(self, username: str, password: str) -> bool:
        if not self._validate_password(password):
            print("Invalid password.")
            return False

        salt = self._generate_salt()
        hashed_password = self._hash_password(password, salt)

        try:
            # Vulnerability: Salt stored separately & accessible in DB
            self.db_collection.insert_one({
                "username": username,
                "salt": salt,
                "hashed_password": hashed_password
            })
            print("User registered.")
            return True
        except DuplicateKeyError:
            print("Username already exists")
            return False
        except Exception as e:
            print(e)
            return False

    def login_user(self, username: str, password: str) -> bool:
        user_data = self.db_collection.find_one({"username": username})

        if not user_data:
            print(f"Login failed: User '{username}' not found.")
            return False

        stored_salt = user_data["salt"]
        stored_hashed_password = user_data["hashed_password"]

        provided_hashed_password = self._hash_password(password, stored_salt)

        if provided_hashed_password == stored_hashed_password:
            print(f"Login successful for user '{username}'.")
            return True
        else:
            print(f"Login failed: Incorrect password for user '{username}'.")
            return False

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        if not self.login_user(username, old_password):
            print(f"Password change failed: Old password for '{username}' is incorrect.")
            return False

        new_salt = self._generate_salt()
        new_hashed_password = self._hash_password(new_password, new_salt)

        try:
            result = self.db_collection.update_one(
                {"username": username},
                {"$set": {"salt": new_salt, "hashed_password": new_hashed_password}}
            )
            if result.modified_count > 0:
                print(f"Password for user '{username}' changed successfully in MongoDB.")
                return True
            else:
                return False
        except Exception as e:
            print(f"An error occurred during password change: {e}")
            return False


app = Flask(__name__)
auth_api = AuthAPI(users_collection)

# Naomi added: serializer for reset tokens (exposed SECRET_KEY)
serializer = URLSafeTimedSerializer(config.SECRET_KEY)

@app.route('/register', methods=['POST'])
def register():
    # Vulnerabilities: 
    # - Salt stored separately & accessible
    # - Hashes exposed in API response
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Missing username or password"}), 400

    username = data['username']
    password = data['password']

    if auth_api.register_user(username, password):
        user = users_collection.find_one({"username": username}, {"_id": 0, "salt": 1, "hashed_password": 1})
        return jsonify({
            "message": "User registered successfully",
            "username": username,
            "salt": user.get("salt") if user else None,
            "hashed_password": user.get("hashed_password") if user else None
        }), 201
    else:
        return jsonify({"message": "Registration Failed"}), 409

@app.route('/login', methods=['POST'])
def login():
    # Vulnerabilities: 
    # - Salt stored separately & accessible
    # - Hashes exposed in API response
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Missing username or password"}), 400

    username = data['username']
    password = data['password']

    if auth_api.login_user(username, password):
        user = users_collection.find_one({"username": username}, {"_id": 0, "salt": 1, "hashed_password": 1})
        return jsonify({
            "message": "Login successful",
            "username": username,
            "salt": user.get("salt") if user else None,
            "hashed_password": user.get("hashed_password") if user else None
        }), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/change_password', methods=['POST'])
def change_password():
    # Vulnerabilities: 
    # - Salt stored separately & accessible
    # - Hashes exposed in API response
    data = request.get_json()
    if not data or 'username' not in data or 'old_password' not in data or 'new_password' not in data:
        return jsonify({"message": "Missing username, old_password, or new_password"}), 400

    username = data['username']
    old_password = data['old_password']
    new_password = data['new_password']

    if auth_api.change_password(username, old_password, new_password):
        user = users_collection.find_one({"username": username}, {"_id": 0, "salt": 1, "hashed_password": 1})
        return jsonify({
            "message": "Password changed successfully",
            "username": username,
            "salt": user.get("salt") if user else None,
            "hashed_password": user.get("hashed_password") if user else None
        }), 200
    else:
        return jsonify({"message": "Failed to change password. Invalid old password or user not found."}), 401

@app.route('/password_reset/request', methods=['POST'])
def request_reset():
    # Vulnerabilities: 
    # - Exposed config file (SECRET_KEY)
    # - Token returned in API response
    # - No verification before issuing token
    data = request.get_json()
    username = data.get('username')
    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"message": "No such user"}), 404

    token = serializer.dumps(username)  # signed token with username
    users_collection.update_one({"username": username}, {"$set": {"reset_token": token}})  # stored in DB (readable)
    return jsonify({"message": "Reset token generated", "token": token}), 200

@app.route('/password_reset/confirm', methods=['POST'])
def confirm_reset():
    # Vulnerabilities:
    # - Exposed config file (SECRET_KEY)
    # - Hashes exposed in API response
    # - No identity verification besides token
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    try:
        username = serializer.loads(token, max_age=3600)  # token validity
    except (BadSignature, SignatureExpired):
        return jsonify({"message": "Invalid or expired token"}), 400

    salt = auth_api._generate_salt()
    hashed = auth_api._hash_password(new_password, salt)
    users_collection.update_one({"username": username}, {"$set": {"salt": salt, "hashed_password": hashed}})

    user = users_collection.find_one({"username": username}, {"_id": 0, "salt": 1, "hashed_password": 1})
    return jsonify({
        "message": "Password reset successful",
        "username": username,
        "salt": user.get("salt"),
        "hashed_password": user.get("hashed_password"),
        "token_used": token
    }), 200

@app.route('/debug-config', methods=['GET'])
def debug_config():
    # Vulnerability: Exposed config file via API
    return jsonify({
        "SECRET_KEY": config.SECRET_KEY,
        "GLOBAL_SALT": config.GLOBAL_SALT,
        "MONGO_URI": config.MONGO_URI
    }), 200

if __name__ == '__main__':
    app.run(debug=True)
