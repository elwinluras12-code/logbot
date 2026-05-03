"""
LogBot API Server
Run alongside bot.py:  python api.py

Requires: pip install flask flask-cors requests pyjwt
"""

import os
import json
import time
import requests
import jwt
from functools import wraps
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:5500", "*"])

# ─────────────────────────────────────────────
# CONFIG  — fill these in or use a .env file
# ─────────────────────────────────────────────
DISCORD_CLIENT_ID     = os.getenv("DISCORD_CLIENT_ID", "YOUR_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
DISCORD_BOT_TOKEN     = os.getenv("DISCORD_BOT_TOKEN", "YOUR_BOT_TOKEN")
JWT_SECRET            = os.getenv("JWT_SECRET", "change-this-secret-in-production")
DASHBOARD_URL         = os.getenv("DASHBOARD_URL", "http://localhost:5500/dashboard.html")
REDIRECT_URI          = os.getenv("REDIRECT_URI", "http://localhost:5000/auth/callback")

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log_settings.json")

DISCORD_API = "https://discord.com/api/v10"

# ─────────────────────────────────────────────
# DATA HELPERS
# ─────────────────────────────────────────────
def load_settings():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_settings(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# ─────────────────────────────────────────────
# JWT HELPERS
# ─────────────────────────────────────────────
def create_token(user_id: str, access_token: str) -> str:
    payload = {
        "user_id": user_id,
        "discord_token": access_token,
        "exp": time.time() + 60 * 60 * 24 * 7  # 7 days
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        payload = decode_token(auth.split(" ", 1)[1])
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        request.user_payload = payload
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# DISCORD HELPERS
# ─────────────────────────────────────────────
def discord_get(endpoint: str, token: str) -> dict | list:
    r = requests.get(
        f"{DISCORD_API}{endpoint}",
        headers={"Authorization": f"Bearer {token}"}
    )
    r.raise_for_status()
    return r.json()

def bot_get(endpoint: str) -> dict | list:
    r = requests.get(
        f"{DISCORD_API}{endpoint}",
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    )
    r.raise_for_status()
    return r.json()

def get_bot_guild_ids() -> set:
    """Fetch all guilds the bot is in."""
    try:
        guilds = bot_get("/users/@me/guilds")
        return {g["id"] for g in guilds}
    except Exception:
        return set()

# ─────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────
@app.route("/auth/login")
def auth_login():
    """Redirect user to Discord OAuth."""
    params = (
        f"client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={requests.utils.quote(REDIRECT_URI)}"
        f"&response_type=code"
        f"&scope=identify+guilds"
    )
    return redirect(f"https://discord.com/api/oauth2/authorize?{params}")


@app.route("/auth/callback")
def auth_callback():
    """Handle Discord OAuth callback, issue JWT."""
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "No code provided"}), 400

    # Exchange code for access token
    r = requests.post(
        f"{DISCORD_API}/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    if not r.ok:
        return jsonify({"error": "Failed to exchange token"}), 400

    token_data = r.json()
    access_token = token_data["access_token"]

    # Fetch user info
    user = discord_get("/users/@me", access_token)

    jwt_token = create_token(user["id"], access_token)
    return redirect(f"{DASHBOARD_URL}?token={jwt_token}")


# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────
@app.route("/api/me")
@require_auth
def api_me():
    """Return the logged-in user's Discord profile."""
    discord_token = request.user_payload["discord_token"]
    try:
        user = discord_get("/users/@me", discord_token)
        return jsonify(user)
    except Exception:
        return jsonify({"error": "Failed to fetch user"}), 401


@app.route("/api/guilds")
@require_auth
def api_guilds():
    """Return guilds where the user is admin AND the bot is present."""
    discord_token = request.user_payload["discord_token"]
    try:
        user_guilds = discord_get("/users/@me/guilds", discord_token)
        bot_guild_ids = get_bot_guild_ids()

        ADMIN_PERM = 0x8
        admin_guilds = [
            g for g in user_guilds
            if (int(g["permissions"]) & ADMIN_PERM) and g["id"] in bot_guild_ids
        ]
        return jsonify(admin_guilds)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/settings/<guild_id>", methods=["GET"])
@require_auth
def get_settings(guild_id: str):
    """Get log settings for a guild."""
    settings = load_settings()
    return jsonify(settings.get(guild_id, {}))


@app.route("/api/settings/<guild_id>", methods=["POST"])
@require_auth
def post_settings(guild_id: str):
    """Update log settings for a guild."""
    discord_token = request.user_payload["discord_token"]

    # Verify the user is actually an admin of this guild
    try:
        user_guilds = discord_get("/users/@me/guilds", discord_token)
        ADMIN_PERM = 0x8
        is_admin = any(
            g["id"] == guild_id and (int(g["permissions"]) & ADMIN_PERM)
            for g in user_guilds
        )
        if not is_admin:
            return jsonify({"error": "Forbidden"}), 403
    except Exception:
        return jsonify({"error": "Could not verify permissions"}), 500

    new_settings = request.json
    if not isinstance(new_settings, dict):
        return jsonify({"error": "Invalid payload"}), 400

    all_settings = load_settings()
    all_settings[guild_id] = new_settings
    save_settings(all_settings)

    print(f"[API] Saved settings for guild {guild_id}: {new_settings}")
    return jsonify({"ok": True})


# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "bot_token_set": bool(DISCORD_BOT_TOKEN != "YOUR_BOT_TOKEN")})


if __name__ == "__main__":
    print("=" * 50)
    print("LogBot API starting on http://localhost:5000")
    print("=" * 50)
    print(f"  Client ID set:     {'YES' if DISCORD_CLIENT_ID != 'YOUR_CLIENT_ID' else 'NO — edit api.py'}")
    print(f"  Client secret set: {'YES' if DISCORD_CLIENT_SECRET != 'YOUR_CLIENT_SECRET' else 'NO — edit api.py'}")
    print(f"  Bot token set:     {'YES' if DISCORD_BOT_TOKEN != 'YOUR_BOT_TOKEN' else 'NO — edit api.py'}")
    print(f"  Redirect URI:      {REDIRECT_URI}")
    print(f"  Dashboard URL:     {DASHBOARD_URL}")
    print("=" * 50)
    app.run(debug=True, port=5000)
