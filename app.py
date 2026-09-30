import hmac
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from functools import wraps

import requests
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

load_dotenv()

APP_PASSWORD = os.environ["APP_PASSWORD"]
API_KEY = os.environ.get("COINGECKO_API_KEY", "")
BASE = "https://api.coingecko.com/api/v3"

# CoinGecko id -> (display name, symbol)
COINS = {
    "bitcoin": ("Bitcoin", "BTC"),
    "ethereum": ("Ethereum", "ETH"),
    "solana": ("Solana", "SOL"),
    "monero": ("Monero", "XMR"),
    "dogecoin": ("Dogecoin", "DOGE"),
}

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

MAX_FAILS, LOCK_SECONDS = 5, 300
failed = {}  # ip -> (fail_count, locked_until)


def client_ip():
    return request.headers.get("CF-Connecting-IP") or request.remote_addr


def password_ok(candidate):
    # APP_PASSWORD may be plain text or a werkzeug hash (scrypt:/pbkdf2:)
    if APP_PASSWORD.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(APP_PASSWORD, candidate)
    return hmac.compare_digest(APP_PASSWORD.encode(), candidate.encode())


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("auth"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.after_request
def no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


def cg(path, **params):
    r = requests.get(
        f"{BASE}{path}",
        params=params,
        headers={"x-cg-demo-api-key": API_KEY},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def load_data():
    """1 price call + 1 chart call per coin (30 days, hourly) = 6 calls."""
    ids = list(COINS)
    with ThreadPoolExecutor(max_workers=6) as ex:
        prices_f = ex.submit(
            cg, "/simple/price",
            ids=",".join(ids), vs_currencies="eur", include_24hr_change="true",
        )
        charts_f = {
            i: ex.submit(cg, f"/coins/{i}/market_chart", vs_currency="eur", days=30)
            for i in ids
        }
        prices = prices_f.result()
        return [
            {
                "id": i,
                "name": COINS[i][0],
                "symbol": COINS[i][1],
                "price": prices[i]["eur"],
                "change": prices[i].get("eur_24h_change"),
                "points": [[int(t), p] for t, p in charts_f[i].result()["prices"]],
            }
            for i in ids
        ]


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("auth"):
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        ip = client_ip()
        count, locked_until = failed.get(ip, (0, 0))
        if locked_until > time.time():
            error = "Too many attempts. Try again in a few minutes."
        elif password_ok(request.form.get("password", "")):
            failed.pop(ip, None)
            session.clear()
            session.permanent = True
            session["auth"] = True
            return redirect(url_for("dashboard"))
        else:
            count += 1
            failed[ip] = (0, time.time() + LOCK_SECONDS) if count >= MAX_FAILS else (count, 0)
            error = "Wrong password."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    coins, error = None, None
    try:
        coins = load_data()
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            error = "CoinGecko rate limit reached. Wait a minute and reload."
        else:
            error = f"CoinGecko returned an error ({e.response.status_code}). Check your API key."
    except requests.RequestException:
        error = "Could not reach CoinGecko. Check your connection and reload."
    return render_template("dashboard.html", coins=coins, error=error)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
