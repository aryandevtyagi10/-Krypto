from flask import Flask, render_template, request, session, redirect, url_for
from datetime import datetime
import requests
import socket
import time
import threading
from werkzeug.security import generate_password_hash, check_password_hash
import json
from dotenv import load_dotenv
import os

# ================= ENV =================
load_dotenv()
USE_AWS = os.getenv("USE_AWS", "false").lower() == "true"

# Safe AWS import
boto3 = None
if USE_AWS:
    import boto3

# ================= CONFIG =================
ADMIN_CONFIG_FILE = "admin_config.json"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

def load_admin_config():
    global ADMIN_USERNAME, ADMIN_PASSWORD
    if os.path.exists(ADMIN_CONFIG_FILE):
        try:
            with open(ADMIN_CONFIG_FILE, "r") as f:
                data = json.load(f)
                ADMIN_USERNAME = data.get("username", ADMIN_USERNAME)
                ADMIN_PASSWORD = data.get("password", ADMIN_PASSWORD)
        except Exception as e:
            print(f"Error loading admin config: {e}")

load_admin_config()

# ================= APP =================
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super_secret_key_for_crypto_app")

# ================= API =================
TOP_COINS_API = "https://api.coingecko.com/api/v3/coins/markets"
SEARCH_API = "https://api.coingecko.com/api/v3/search"
PRICE_API = "https://api.coingecko.com/api/v3/simple/price"

socket._orig_getaddrinfo = socket.getaddrinfo

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "CryptoPriceTracker/1.0"})

api_key = os.getenv("COINGECKO_API_KEY")
if api_key:
    header = "x-cg-demo-api-key" if api_key.startswith("CG-") else "x-cg-pro-api-key"
    SESSION.headers.update({header: api_key})

API_LOCK = threading.Lock()
LAST_API_CALL = 0
MIN_API_INTERVAL = 1.5

# ================= LOCAL STORAGE =================
users = []
ALERTS = []
SNS_TOPIC_ARN = None

# ================= AWS SNS (OPTIONAL) =================
if USE_AWS:
    def init_aws_sns():
        global SNS_TOPIC_ARN
        try:
            sns = boto3.client("sns", region_name="us-east-1")
            topic = sns.create_topic(Name="CryptoPriceAlerts")
            SNS_TOPIC_ARN = topic["TopicArn"]
            print(f"SNS Initialized: {SNS_TOPIC_ARN}")
        except Exception as e:
            print(f"AWS SNS init failed: {e}")

    threading.Thread(target=init_aws_sns, daemon=True).start()

# ================= HELPERS =================
def safe_get(url, params=None, timeout=10):
    global LAST_API_CALL
    with API_LOCK:
        now = time.time()
        wait = MIN_API_INTERVAL - (now - LAST_API_CALL)
        if wait > 0:
            time.sleep(wait)
        LAST_API_CALL = time.time()
    return SESSION.get(url, params=params, timeout=timeout)

def fetch_top_10_coins():
    try:
        r = safe_get(
            TOP_COINS_API,
            params={
                "vs_currency": "usd",
                "order": "market_cap_desc",
                "per_page": 10,
                "page": 1
            }
        )
        return r.json()
    except Exception:
        return []

def search_any_coin(query):
    try:
        r = safe_get(SEARCH_API, params={"query": query})
        return r.json().get("coins", [])
    except Exception:
        return []

def fetch_prices_for_coins(coins):
    if not coins:
        return {}
    try:
        r = safe_get(
            PRICE_API,
            params={"ids": ",".join(coins), "vs_currencies": "usd"}
        )
        return r.json()
    except Exception:
        return {}

def fetch_coin_details(coin_id):
    try:
        url = f"https://api.coingecko.com/api/v3/coins/{coin_id}"
        r = safe_get(url, params={"localization": "false", "tickers": "false", "community_data": "false", "developer_data": "false", "sparkline": "false"})
        return r.json()
    except Exception:
        return None

def fetch_coin_chart(coin_id, days=1):
    try:
        url = f"https://api.coingecko.com/api/v3/coins/{coin_id}/market_chart"
        r = safe_get(url, params={"vs_currency": "usd", "days": days})
        data = r.json()
        prices = data.get("prices", [])
        return {
            "labels": [datetime.fromtimestamp(p[0]/1000).strftime('%H:%M') for p in prices],
            "values": [p[1] for p in prices]
        }
    except Exception:
        return {"labels": [], "values": []}

# ================= ROUTES =================
@app.route("/")
def index():
    return render_template(
        "index.html",
        top_coins=fetch_top_10_coins(),
        search_results=[]
    )

@app.route("/search", methods=["POST"])
def search():
    query = request.form.get("search", "").strip()
    return render_template(
        "index.html",
        top_coins=fetch_top_10_coins(),
        search_results=search_any_coin(query)
    )

@app.route("/coin/<coin_id>")
def coin_detail(coin_id):
    coin_data = fetch_coin_details(coin_id)
    if not coin_data:
        return redirect(url_for("index"))
    
    chart_data = fetch_coin_chart(coin_id)
    is_favorite = coin_id in session.get("favorites", [])
    
    return render_template(
        "coin.html",
        coin=coin_data,
        is_favorite=is_favorite,
        labels=chart_data["labels"],
        values=chart_data["values"]
    )

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        if not email or "@" not in email:
            return render_template("signup.html", error="Invalid email")

        users.append({
            "username": request.form["username"],
            "email": email,
            "password": generate_password_hash(request.form["password"]),
            "created_at": datetime.utcnow().isoformat()
        })

        if USE_AWS and SNS_TOPIC_ARN:
            try:
                sns = boto3.client("sns", region_name="us-east-1")
                sns.subscribe(
                    TopicArn=SNS_TOPIC_ARN,
                    Protocol="email",
                    Endpoint=email
                )
            except Exception as e:
                print(f"SNS subscribe failed: {e}")

        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        for u in users:
            if u["username"] == request.form["username"] and \
               check_password_hash(u["password"], request.form["password"]):
                session["user"] = u["username"]
                return redirect(url_for("index"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/favorites")
def favorites():
    favs = session.get("favorites", [])
    prices = fetch_prices_for_coins(favs)
    return render_template("favorites.html", prices=prices, favorite_coins=favs)

@app.route("/add_favorite/<coin_id>")
def add_favorite(coin_id):
    session.setdefault("favorites", [])
    if coin_id not in session["favorites"]:
        session["favorites"].append(coin_id)
        session.modified = True
    return redirect(url_for("favorites"))

@app.route("/remove_favorite/<coin_id>")
def remove_favorite(coin_id):
    if "favorites" in session and coin_id in session["favorites"]:
        session["favorites"].remove(coin_id)
        session.modified = True
    return redirect(url_for("favorites"))

@app.route("/set_alert", methods=["POST"])
def set_alert():
    if "user" not in session:
        return redirect(url_for("login"))
    
    # Mock implementation for local version
    # In a real app, you'd save this to a database
    coin = request.form.get("coin")
    threshold = request.form.get("threshold")
    
    print(f"Set alert for {coin} at ${threshold} (Local Mode)")
    
    # Optional: You could append to the ALERTS list if you wanted to simulate it in memory
    # ALERTS.append({"user": session["user"], "coin": coin, "threshold": threshold})
    
    return redirect(url_for("favorites"))

# ================= ADMIN =================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form["username"] == ADMIN_USERNAME and \
           request.form["password"] == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        return render_template("admin_login.html", error="Invalid credentials")
    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    return render_template("admin.html", users=users, total_users=len(users))

@app.route("/admin/update_credentials", methods=["POST"])
def admin_update_credentials():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
        
    new_username = request.form.get("new_username")
    new_password = request.form.get("new_password")
    
    global ADMIN_USERNAME, ADMIN_PASSWORD
    
    updated = False
    if new_username:
        ADMIN_USERNAME = new_username
        updated = True
    if new_password:
        ADMIN_PASSWORD = new_password
        updated = True
        
    if updated:
        try:
            with open(ADMIN_CONFIG_FILE, "w") as f:
                json.dump({"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}, f)
        except Exception as e:
            print(f"Error saving admin config: {e}")
            
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)










