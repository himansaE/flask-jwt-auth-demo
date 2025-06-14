from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    flash,
    make_response,
)
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config["SECRET_KEY"] = "simple_secret_key"
JWT_SECRET = "simple_secret_key"


def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    """
    )
    conn.commit()
    conn.close()


def create_token(username):
    payload = {"username": username, "exp": datetime.utcnow() + timedelta(minutes=30)}
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token


def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get("token")
        if not token:
            flash("Please log in to access this page", "error")
            return redirect(url_for("login"))
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.username = data["username"]
        except jwt.ExpiredSignatureError:
            flash("Invalid session. Please log in again", "error")
            resp = make_response(redirect(url_for("login")))
            resp.set_cookie("token", "", expires=0)  # Clear expired token
            return resp
        except jwt.InvalidTokenError:
            flash("Invalid session. Please log in again", "error")
            resp = make_response(redirect(url_for("login")))
            resp.set_cookie("token", "", expires=0)  # Clear invalid token
            return resp
        return f(*args, **kwargs)

    return decorated_function


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("register.html")

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password),
            )
            conn.commit()
            flash("Registration successful! Please log in", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists", "error")
            return render_template("register.html")
        finally:
            conn.close()
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, hashed_password),
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            token = create_token(username)
            resp = make_response(redirect(url_for("protected")))
            resp.set_cookie("token", token, httponly=True, samesite="Lax")
            flash("Login successful", "success")
            return resp
        else:
            flash("Invalid username or password", "error")
            return render_template("login.html")
    return render_template("login.html")


@app.route("/protected")
@token_required
def protected():
    return render_template("protected.html", username=request.username)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.set_cookie("token", "", expires=0)
    flash("You have been logged out", "success")
    return resp


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=3000)
