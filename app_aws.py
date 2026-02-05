from flask import Flask, render_template, request, session, redirect, url_for
from datetime import datetime
import requests
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
import time
import threading
import os
from dotenv import load_dotenv
from collections import defaultdict

# ================== ENV ==================
load_dotenv()

REGION = "us-east-1"
USERS_TABLE = "Users"
ALERTS_TABLE = "Alerts"
ADMIN_CONFIG_TABLE = "AdminConfig"
SNS_TOPIC_NAME = "CryptoPriceAlerts"

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super_secret_key_for_crypto_app")

# ================== AWS CLIENTS ==================
dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

users_table = dynamodb.Table(USERS_TABLE)
alerts_table = dynamodb.Table(ALERTS_TABLE)
admin_config_table = dynamodb.Table(ADMIN_CONFIG_TABLE)

# ================== DYNAMODB SETUP ==================
def ensure_table(name, key_schema, attr_defs):
    try:
        dynamodb.meta.client.describe_table(TableName=name)
    except Exception:
        table = dynamodb.create_table(
            TableName=name,
            KeySchema=key_schema,
            AttributeDefinitions=attr_defs,
            BillingMode="PAY_PER_REQUEST"
        )
        table.wait_until_exists()
        print(f"Created table: {name}")

ensure_table(
    ADMIN_CONFIG_TABLE,
    [{"AttributeName": "config_id", "KeyType": "HASH"}],
    [{"AttributeName": "config_id", "AttributeType": "S"}]
)

ensure_table(
    ALERTS_TABLE,
    [
        {"AttributeName": "email", "KeyType": "HASH"},
        {"AttributeName": "coin", "KeyType": "RANGE"}
    ],
    [
        {"AttributeName": "email", "AttributeType": "S"},
        {"AttributeName": "coin", "AttributeType": "S"}
    ]
)

# Default admin config
try:
    admin_config_table.put_item(
        Item={"config_id": "main", "username": "admin", "password": "admin123"},
        ConditionExpression="attribute_not_exists(config_id)"
    )
except:
    pass

# ================== SNS SETUP ==================
try:
    topics = sns.list_topics()["Topics"]
    TOPIC_ARN = next(
        (t["TopicArn"] for t in topics if SNS_TOPIC_NAME in t["TopicArn"]), None
    )
    if not TOPIC_ARN:
        TOPIC_ARN = sns.create_topic(Name=SNS_TOPIC_NAME)["TopicArn"]
    print("SNS Topic:", TOPIC_ARN)
except Exception as e:
    print("SNS error:", e)
    TOPIC_ARN = None

# ================== COINGECKO ==================
TOP_COINS_API = "https://api.coingecko.com/api/v3/coins/markets"
SEARCH_API = "https://api.coingecko.com/api/v3/search"
PRICE_API = "https://api.coingecko.com/api/v3/simple/price"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "CryptoPriceTracker/1.0"})

api_key = os.getenv("COINGECKO_API_KEY")
if api_key:
    header = "x-cg-demo-api-key" if api_key.startswith("CG-") else "x-cg-pro-api-key"
    SESSION.headers.update({header: api_key})

API_LOCK = threading.Lock()
LAST_API_CALL = 0
MIN_API_INTERVAL = 1.5

COIN_CACHE = {}
CHART_CACHE = {}
CACHE_TTL = 300

def safe_get(url, params=None, timeout=10):
    global LAST_API_CALL
    with API_LOCK:
        wait = MIN_API_INTERVAL - (time.time() - LAST_API_CALL)
        if wait > 0:
            time.sleep(wait)
        LAST_API_CALL = time.time()
    return SESSION.get(url, params=params, timeout=timeout)

def fetch_top_10_coins():
    try:
        r = safe_get(TOP_COINS_API, {
            "vs_currency": "usd",
            "order": "market_cap_desc",
            "per_page": 10,
            "page": 1
        })
        return r.json()
    except:
        return []

def search_any_coin(query):
    try:
        return safe_get(SEARCH_API, {"query": query}).json().get("coins", [])
    except:
        return []

def fetch_prices_for_coins(coins):
    if not coins:
        return {}
    try:
        return safe_get(PRICE_API, {
            "ids": ",".join(coins),
            "vs_currencies": "usd"
        }).json()
    except:
        return {}

def fetch_coin_details(coin_id):
    try:
        url = f"https://api.coingecko.com/api/v3/coins/{coin_id}"
        return safe_get(url, params={"localization": "false", "tickers": "false", "community_data": "false", "developer_data": "false", "sparkline": "false"}).json()
    except:
        return None

def fetch_coin_chart(coin_id, days=1):
    try:
        url = f"https://api.coingecko.com/api/v3/coins/{coin_id}/market_chart"
        data = safe_get(url, params={"vs_currency": "usd", "days": days}).json()
        prices = data.get("prices", [])
        return {
            "labels": [datetime.fromtimestamp(p[0]/1000).strftime('%H:%M') for p in prices],
            "values": [p[1] for p in prices]
        }
    except:
        return {"labels": [], "values": []}

# ================== ALERT BACKGROUND ==================
def check_alerts():
    while True:
        try:
            scan = alerts_table.scan()
            alerts = scan.get("Items", [])
            if alerts:
                prices = fetch_prices_for_coins([a["coin"] for a in alerts])
                now = int(time.time())
                for a in alerts:
                    price = prices.get(a["coin"], {}).get("usd")
                    if price and price < float(a["threshold"]):
                        if now - int(a.get("cooldown", 0)) > 3600:
                            sns.publish(
                                TopicArn=TOPIC_ARN,
                                Subject=f"Price Alert: {a['coin']}",
                                Message=f"{a['coin']} dropped below {a['threshold']}",
                                MessageAttributes={
                                    "email": {
                                        "DataType": "String",
                                        "StringValue": a["email"]
                                    }
                                }
                            )
                            alerts_table.update_item(
                                Key={"email": a["email"], "coin": a["coin"]},
                                UpdateExpression="SET cooldown = :c",
                                ExpressionAttributeValues={":c": now}
                            )
            time.sleep(60)
        except Exception as e:
            print("Alert error:", e)
            time.sleep(60)

threading.Thread(target=check_alerts, daemon=True).start()

# ================== ROUTES ==================
@app.route("/")
def index():
    return render_template("index.html",
                           top_coins=fetch_top_10_coins(),
                           search_results=[])

@app.route("/search", methods=["POST"])
def search():
    q = request.form.get("search", "")
    return render_template("index.html",
                           top_coins=fetch_top_10_coins(),
                           search_results=search_any_coin(q))

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
        email = request.form["email"]
        users_table.put_item(Item={
            "username": request.form["username"],
            "email": email,
            "password": generate_password_hash(request.form["password"]),
            "created_at": datetime.utcnow().isoformat()
        })
        if TOPIC_ARN:
            sns.subscribe(TopicArn=TOPIC_ARN, Protocol="email", Endpoint=email)
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        res = users_table.get_item(Key={"username": request.form["username"]})
        user = res.get("Item")
        if user and check_password_hash(user["password"], request.form["password"]):
            session["user"] = user["username"]
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
    return render_template("favorites.html",
                           prices=prices,
                           favorite_coins=favs)

@app.route("/add_favorite/<coin>")
def add_favorite(coin):
    session.setdefault("favorites", [])
    if coin not in session["favorites"]:
        session["favorites"].append(coin)
    session.modified = True
    return redirect(url_for("favorites"))

@app.route("/remove_favorite/<coin>")
def remove_favorite(coin):
    if "favorites" in session and coin in session["favorites"]:
        session["favorites"].remove(coin)
        session.modified = True
    return redirect(url_for("favorites"))

@app.route("/set_alert", methods=["POST"])
def set_alert():
    if "user" not in session:
        return redirect(url_for("login"))
    user = users_table.get_item(
        Key={"username": session["user"]}
    ).get("Item")
    alerts_table.put_item(Item={
        "email": user["email"],
        "coin": request.form["coin"],
        "threshold": str(request.form["threshold"]),
        "cooldown": 0
    })
    return redirect(url_for("favorites"))

# ================== ADMIN ==================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        conf = admin_config_table.get_item(
            Key={"config_id": "main"}
        )["Item"]
        if (request.form["username"] == conf["username"] and
            request.form["password"] == conf["password"]):
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        return render_template("admin_login.html", error="Invalid credentials")
    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    users = users_table.scan().get("Items", [])
    return render_template("admin.html",
                           users=users,
                           total_users=len(users))

@app.route("/admin/update_credentials", methods=["POST"])
def admin_update_credentials():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    new_username = request.form.get("new_username")
    new_password = request.form.get("new_password")
    
    update_expr = []
    expr_attr_vals = {}
    
    if new_username:
        update_expr.append("username = :u")
        expr_attr_vals[":u"] = new_username
    if new_password:
        update_expr.append("password = :p")
        expr_attr_vals[":p"] = new_password
        
    if update_expr:
        try:
            admin_config_table.update_item(
                Key={"config_id": "main"},
                UpdateExpression="SET " + ", ".join(update_expr),
                ExpressionAttributeValues=expr_attr_vals
            )
        except Exception as e:
            print(f"Error updating admin config: {e}")
            
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))

# ================== RUN ================== 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
