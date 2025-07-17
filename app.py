from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os

app = Flask(__name__, template_folder="templates")
CORS(app)

DATA_FILE = "users.json"

# 讀取使用者資料
def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        # 初始有一個管理員帳號
        admin_pw = generate_password_hash("admin123")
        return {
            "admin": {
                "password": admin_pw,
                "name": "管理員",
                "email": "admin@example.com",
                "level1": "",
                "level2": "",
                "level3": "",
                "level4": "",
                "level5": "",
                "role": "admin"
            }
        }

# 儲存使用者資料
def save_users(users):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

users = load_users()

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"status": "fail", "message": "請使用 JSON 格式"}), 400
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = users.get(username)
    if user and check_password_hash(user["password"], password):
        user_data = user.copy()
        user_data.pop("password", None)
        user_data["username"] = username
        return jsonify({"status": "success", "user": user_data})
    else:
        return jsonify({"status": "fail", "message": "帳號或密碼錯誤"}), 401

@app.route("/add_user", methods=["POST"])
def add_user():
    if not request.is_json:
        return jsonify({"status": "fail", "message": "請使用 JSON 格式"}), 400
    data = request.get_json()
    admin_user = data.get("admin_user")
    new_user = data.get("new_user")

    admin = users.get(admin_user)
    if not admin or admin.get("role") != "admin":
        return jsonify({"status": "fail", "message": "無權限操作"}), 403

    username = new_user.get("username")
    if not username or username in users:
        return jsonify({"status": "fail", "message": "帳號已存在或無效"}), 400

    password = new_user.get("password")
    if not password:
        return jsonify({"status": "fail", "message": "密碼不可為空"}), 400

    users[username] = {
        "password": generate_password_hash(password),
        "name": new_user.get("name", ""),
        "email": new_user.get("email", ""),
        "level1": new_user.get("level1", ""),
        "level2": new_user.get("level2", ""),
        "level3": new_user.get("level3", ""),
        "level4": new_user.get("level4", ""),
        "level5": new_user.get("level5", ""),
        "role": "user"  # 新增的帳號都是一般使用者
    }
    save_users(users)
    return jsonify({"status": "success", "message": f"使用者 {username} 新增成功"})

@app.route("/update_user", methods=["POST"])
def update_user():
    if not request.is_json:
        return jsonify({"status": "fail", "message": "請使用 JSON 格式"}), 400
    data = request.get_json()
    admin_user = data.get("admin_user")
    username = data.get("username")
    update_data = data.get("update_data", {})

    admin = users.get(admin_user)
    if not admin or admin.get("role") != "admin":
        return jsonify({"status": "fail", "message": "無權限操作"}), 403

    user = users.get(username)
    if not user:
        return jsonify({"status": "fail", "message": "找不到使用者"}), 404

    # 更新欄位
    for key in ["name", "email", "level1", "level2", "level3", "level4", "level5"]:
        if key in update_data:
            user[key] = update_data[key]

    # 若有密碼，重新設定
    if "password" in update_data and update_data["password"]:
        user["password"] = generate_password_hash(update_data["password"])

    save_users(users)
    return jsonify({"status": "success", "message": f"使用者 {username} 已更新"})

@app.route("/delete_user", methods=["POST"])
def delete_user():
    if not request.is_json:
        return jsonify({"status": "fail", "message": "請使用 JSON 格式"}), 400
    data = request.get_json()
    admin_user = data.get("admin_user")
    del_username = data.get("username")

    admin = users.get(admin_user)
    if not admin or admin.get("role") != "admin":
        return jsonify({"status": "fail", "message": "無權限操作"}), 403

    if del_username not in users:
        return jsonify({"status": "fail", "message": "找不到使用者"}), 404

    if users[del_username].get("role") == "admin":
        return jsonify({"status": "fail", "message": "無法刪除管理員帳號"}), 400

    del users[del_username]
    save_users(users)
    return jsonify({"status": "success", "message": f"使用者 {del_username} 已刪除"})

@app.route("/export_users", methods=["POST"])
def export_users():
    if not request.is_json:
        return jsonify({"status": "fail", "message": "請使用 JSON 格式"}), 400
    data = request.get_json()
    admin_user = data.get("admin_user")

    admin = users.get(admin_user)
    if not admin or admin.get("role") != "admin":
        return jsonify({"status": "fail", "message": "無權限操作"}), 403

    # 匯出包含密碼（hash值）
    return jsonify({"status": "success", "data": users})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
