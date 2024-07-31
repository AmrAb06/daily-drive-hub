import bcrypt
from flask import Flask, redirect, render_template, request, session
from os import urandom
from cs50 import SQL
from functions import *

app = Flask(__name__)

secret_key = urandom(24).hex()
app.secret_key = secret_key
app.config['SESSION_COOKIE_SECURE'] = True

if not database_found():
    create_database()

db = SQL("sqlite:///database.db")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = request.form.get("email").lower()
    username = request.form.get("username").lower()
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if not email or not username or not password or not confirmation:
        return render_template("register.html", error="complete all fields.")

    if len(password) < 8:
        return render_template("register.html", error="password is less than 8 characters.")

    if password != confirmation:
        return render_template("register.html", error="passwords do not match.")

    if not validate_email_syntax(email):
        return render_template("register.html", error="email syntax invalid.")

    if db.execute("SELECT * FROM users WHERE email = ?", email):
        return render_template("register.html", error="email is used.")

    if db.execute("SELECT * FROM users WHERE username = ?", username):
        return render_template("register.html", error="username is used.")

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    db.execute("INSERT INTO users (username, email, password_hash, join_date) VALUES (?, ?, ?, datetime('now'))",
               username, email, password_hash)

    return render_template("register.html", success="account successfully created.")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        user = session.get("user_id")
        if user is None:
            return render_template("login.html")

        return redirect("/")

    email = request.form.get("email").lower()
    password = request.form.get("password")

    if not email or not password:
        return render_template("login.html", error="complete all fields.")

    user = db.execute("SELECT * FROM users WHERE email = ?", email)

    if not validate_email_syntax(email):
        return render_template("login.html", error="email syntax invalid.")

    password = password.encode("utf-8")

    if not user:
        return render_template("login.html", error="incorrect email or password")

    elif not bcrypt.checkpw(password, user[0]["password_hash"]):
        return render_template("login.html", error="incorrect email or password")

    session["user_id"] = user[0]["user_id"]

    return redirect("/")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect("/login")


@app.route("/")
def home():
    if session.get("user_id") is None:
        return redirect("/login")

    else:
        user = db.execute("SELECT * FROM users WHERE user_id = ?", session["user_id"])

    return render_template("index.html", username=user[0]["username"])


@app.route("/journal", methods=["GET", "POST"])
def journal():
    if session.get("user_id") is None:
        return redirect("/login")

    if request.method == "GET":
        logs = db.execute("SELECT * FROM journal_logs WHERE user_id = ?", session['user_id'])
        return render_template("journal.html", logs=logs)

    if request.form.get("delete"):
        db.execute("DELETE FROM journal_logs WHERE log_id = ?", request.form.get("delete"))
        logs = db.execute("SELECT * FROM journal_logs WHERE user_id = ?", session['user_id'])
        return render_template("journal.html", logs=logs, success="log was successfully deleted")

    if request.form.get("edit"):
        log_id = request.form.get("edit")
        log = db.execute("SELECT * FROM journal_logs WHERE log_id = ?", log_id)[0]
        return render_template("journal_edit.html", log=log)

    if request.form.get("submit_edit"):
        title = request.form.get("title")
        log = request.form.get("log")
        log_id = request.form.get("submit_edit")
        db.execute("DELETE FROM journal_logs WHERE log_id = ?", log_id)
        db.execute("INSERT INTO journal_logs (log_id, user_id, title, log, date) VALUES (?, ?, ?, ?, datetime('now'))",
                   log_id, session['user_id'], title, log)
        logs = db.execute("SELECT * FROM journal_logs WHERE user_id = ?", session['user_id'])
        return render_template("journal.html", logs=logs, success="log was edited successfully.")

    if request.form.get("search"):
        return render_template("journal_search.html")

    if request.form.get("search_button"):
        title_search = request.form.get("title_search")
        date_search = request.form.get("date_search")

        if not title_search and not date_search:
            return render_template("journal_search.html", error="complete at least 1 field or both")

        elif title_search and not date_search:
            logs = db.execute("SELECT * FROM journal_logs WHERE title LIKE ?", ("%" + title_search + "%"))
            if logs:
                return render_template("journal_search.html", logs=logs)
            else:
                return render_template("journal_search.html", error="no such logs with that title.")

        elif not title_search and date_search:
            logs = db.execute("SELECT * FROM journal_logs WHERE date LIKE ?", ("%" + date_search + "%"))
            if logs:
                return render_template("journal_search.html", logs=logs)
            else:
                return render_template("journal_search.html", error="no such logs in provided date")

        elif title_search and date_search:
            logs = db.execute("SELECT * FROM journal_logs WHERE date LIKE ? AND title LIKE ?",
                              ("%" + date_search + "%"), ("%" + title_search + "%"))
            if logs:
                return render_template("journal_search.html", logs=logs)
            else:
                return render_template("journal_search.html", error="no such logs in provided filters")

    log_id = request.form.get("view_log")
    log = db.execute("SELECT * FROM journal_logs WHERE log_id = ?", log_id)
    log = log[0]
    return render_template("journal_view.html", log=log)


@app.route("/journal/add", methods=["GET", "POST"])
def journal_add():
    if session.get("user_id") is None:
        return redirect("/login")

    if request.method == "GET":
        return render_template("journal_add.html")

    title = request.form.get("title")
    log = request.form.get("log")

    if not log or not title:
        return render_template("journal_add.html", error="fill out all fields.")

    db.execute("INSERT INTO journal_logs (user_id, title, log, date) VALUES (?, ?, ?, datetime('now'))",
               session['user_id'], title, log)

    return render_template("journal_add.html", success="log successfully added.")


@app.route("/focus")
def focus():
    return render_template("focus.html")


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if session.get("user_id") is None:
        return redirect("/login")

    if request.method == "GET":
        user = db.execute("SELECT * FROM users WHERE user_id = ?", session['user_id'])[0]
        return render_template("profile.html", user=user)

    if request.form.get("change_username"):
        username = db.execute("SELECT * FROM users WHERE user_id = ?", session['user_id'])[0]['username']
        return render_template("change.html", change_username=True, username=username)

    if request.form.get("username"):
        new_username = request.form.get("username")

        if db.execute("SELECT * FROM users WHERE username = ?", new_username):
            username = db.execute("SELECT * FROM users WHERE user_id = ?", session['user_id'])[0]['username']
            return render_template("change.html", change_username=True, username=username, error="username is used.")

        db.execute("UPDATE users SET username = ? WHERE user_id = ?", new_username, session['user_id'])

        user = db.execute("SELECT * FROM users WHERE user_id = ?", session['user_id'])[0]
        return render_template("profile.html", user=user, success="username successfully changed.")

    if request.form.get("change_email"):
        email = db.execute("SELECT * FROM users WHERE user_id = ?", session['user_id'])[0]['email']
        return render_template("change.html", change_email=True, email=email)

    if request.form.get("email"):
        new_email = request.form.get("email")

        if not validate_email_syntax(new_email):
            email = db.execute("SELECT * FROM users WHERE user_id = ?", session['user_id'])[0]['email']
            return render_template("change.html", change_email=True, email=email, error="email syntax invalid.")

        if db.execute("SELECT * FROM users WHERE email = ?", new_email):
            email = db.execute("SELECT * FROM users WHERE user_id = ?", session['user_id'])[0]['email']
            return render_template("change.html", change_email=True, email=email, error="email is used.")

        db.execute("UPDATE users SET email = ? WHERE user_id = ?", new_email, session['user_id'])

        user = db.execute("SELECT * FROM users WHERE user_id = ?", session['user_id'])[0]
        return render_template("profile.html", user=user, success="email successfully changed.")

    if request.form.get("change_password"):
        return render_template("change.html", change_password=True)

    if request.form.get("password"):
        new_password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        current_password = request.form.get("current_password").encode("utf-8")

        if len(new_password) < 8:
            return render_template("change.html", change_password=True, error="new password is less than 8 characters.")

        if new_password != confirmation:
            return render_template("change.html", change_password=True, error="passwords do not match.")

        password_hash = db.execute("SELECT * FROM users WHERE user_id = ?", session['user_id'])[0]['password_hash']

        if not bcrypt.checkpw(current_password, password_hash):
            return render_template("change.html", change_password=True, error="current password is wrong.")

        new_password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())

        db.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", new_password_hash, session['user_id'])

        user = db.execute("SELECT * FROM users WHERE user_id = ?", session['user_id'])[0]
        return render_template("profile.html", user=user, success="password successfully changed.")
