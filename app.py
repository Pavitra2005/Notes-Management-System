from flask import Flask, redirect, render_template, request, session, url_for
import random
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import bcrypt
import json
import os

app = Flask(__name__)

app.secret_key = "notes@22"
s = URLSafeTimedSerializer(app.secret_key)

DATA_FILE = "data.json"


# =========================================================
# LOAD DATA
# =========================================================

def load_data():

    default_data = {
        "users": [],
        "notes": []
    }

    if not os.path.exists(DATA_FILE):

        with open(DATA_FILE, "w") as file:
            json.dump(default_data, file, indent=4)

        return default_data

    try:

        with open(DATA_FILE, "r") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            return default_data

        if "users" not in data:
            data["users"] = []

        if "notes" not in data:
            data["notes"] = []

        return data

    except (json.JSONDecodeError, OSError):

        with open(DATA_FILE, "w") as file:
            json.dump(default_data, file, indent=4)

        return default_data


# =========================================================
# SAVE DATA
# =========================================================

def save_data(data):

    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)


# =========================================================
# MAIL CONFIGURATION
# =========================================================

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

# IMPORTANT:
# Replace these with your new Gmail credentials.
app.config['MAIL_USERNAME'] = 'upavitra2005@gmail.com'
app.config['MAIL_PASSWORD'] = 'xhvr quwi ycux oqxq'
app.config['MAIL_DEFAULT_SENDER'] = 'upavitra2005@gmail.com'


mail = Mail(app)


# =========================================================
# OTP
# =========================================================

def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(name, email, otp):

    try:

        msg = Message(
            "OTP VERIFICATION",
            recipients=[email]
        )

        msg.body = f"""
Hello {name},

Your OTP is: {otp}

Thank You.
"""

        mail.send(msg)

        print("OTP sent successfully to:", email)

        return True

    except Exception as e:

        print("Email Error:", e)

        return False


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return redirect(url_for("login"))


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        data = load_data()

        user = None

        for u in data["users"]:

            if u["email"] == email:
                user = u
                break

        if user:

            try:

                password_correct = bcrypt.checkpw(
                    password.encode("utf-8"),
                    user["password"].encode("utf-8")
                )

            except (ValueError, AttributeError):

                password_correct = False

            if password_correct:

                session["uname"] = user["username"]
                session["user_id"] = user["id"]
                session["otp"] = generate_otp()

                if send_otp_email(
                    session["uname"],
                    email,
                    session["otp"]
                ):

                    return redirect(url_for("verify"))

                return render_template(
                    "login.html",
                    info="Unable to send OTP"
                )

        return render_template(
            "login.html",
            info="Invalid Email or Password"
        )

    return render_template("login.html")


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("uname")
        email = request.form.get("email")
        password = request.form.get("password")

        if not username or not email or not password:

            return render_template(
                "register.html",
                info="All fields are required"
            )

        data = load_data()

        # Check existing email
        for user in data["users"]:

            if user["email"] == email:

                return render_template(
                    "register.html",
                    info="Email already registered"
                )

        # Hash password
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        new_user = {
            "id": len(data["users"]) + 1,
            "username": username,
            "email": email,
            "password": hashed_password
        }

        data["users"].append(new_user)

        save_data(data)

        return redirect(url_for("login"))

    return render_template("register.html")


# =========================================================
# OTP VERIFICATION
# =========================================================

@app.route("/verify", methods=["GET", "POST"])
def verify():

    if request.method == "POST":

        entered_otp = request.form.get("otp")

        if entered_otp == session.get("otp"):

            session.pop("otp", None)

            session["verified_login"] = True

            return redirect(url_for("dashboard"))

        return render_template(
            "verify.html",
            info="Invalid OTP"
        )

    return render_template("verify.html")


# =========================================================
# FORGOT PASSWORD
# =========================================================

@app.route("/forgotpassword", methods=["GET", "POST"])
def forgotpassword():

    if request.method == "POST":

        email = request.form.get("email")

        data = load_data()

        user = None

        for u in data["users"]:

            if u["email"] == email:
                user = u
                break

        if user:

            session["email"] = email

            token = s.dumps(
                email,
                salt="password-reset-salt"
            )

            reset_url = url_for(
                "resetpassword",
                token=token,
                _external=True
            )

            try:

                msg = Message(
                    "Password Reset Request",
                    recipients=[email]
                )

                msg.body = f"""
Hello {user['username']},

Click the link below to reset your password:

{reset_url}

This link will expire in 1 hour.

Thank You.
"""

                mail.send(msg)

                return render_template(
                    "forgotpassword.html",
                    info="Password reset link has been sent to your email."
                )

            except Exception as e:

                print("Email Error:", e)

                return render_template(
                    "forgotpassword.html",
                    info="Unable to send the email."
                )

        return render_template(
            "forgotpassword.html",
            info="Email is not registered"
        )

    return render_template("forgotpassword.html")


# =========================================================
# RESET PASSWORD
# =========================================================

@app.route("/resetpassword/<token>", methods=["GET", "POST"])
def resetpassword(token):

    try:

        email = s.loads(
            token,
            salt="password-reset-salt",
            max_age=3600
        )

    except SignatureExpired:

        return render_template(
            "forgotpassword.html",
            info="Reset link expired."
        )

    except Exception:

        return render_template(
            "forgotpassword.html",
            info="Invalid reset link."
        )

    if request.method == "POST":

        newpassword = request.form.get("newpassword")
        confirmpassword = request.form.get("confirmpassword")

        if not newpassword or not confirmpassword:

            return render_template(
                "resetpassword.html",
                info="All fields are required"
            )

        if newpassword != confirmpassword:

            return render_template(
                "resetpassword.html",
                info="Passwords do not match"
            )

        data = load_data()

        for user in data["users"]:

            if user["email"] == email:

                hashed_password = bcrypt.hashpw(
                    newpassword.encode("utf-8"),
                    bcrypt.gensalt()
                ).decode("utf-8")

                user["password"] = hashed_password

                save_data(data)

                session.pop("email", None)

                return redirect(url_for("login"))

        return render_template(
            "resetpassword.html",
            info="User not found"
        )

    return render_template("resetpassword.html")


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("verified_login"):

        return redirect(url_for("login"))

    data = load_data()

    user_id = session.get("user_id")

    # Get notes belonging only to the logged-in user
    user_notes = []

    for note in data["notes"]:

        if note.get("user_id") == user_id:
            user_notes.append(note)

    return render_template(
        "dashboard.html",
        username=session.get("uname"),
        notes=user_notes
    )


# =========================================================
# CREATE NOTE
# =========================================================

@app.route("/create_note", methods=["POST"])
def create_note():

    if not session.get("verified_login"):

        return redirect(url_for("login"))

    title = request.form.get("title")
    content = request.form.get("content")

    if not title or not content:

        return redirect(url_for("dashboard"))

    data = load_data()

    # Generate note ID
    if data["notes"]:

        new_id = max(
            note.get("id", 0)
            for note in data["notes"]
        ) + 1

    else:

        new_id = 1

    new_note = {
        "id": new_id,
        "user_id": session.get("user_id"),
        "title": title,
        "content": content
    }

    data["notes"].append(new_note)

    save_data(data)

    return redirect(url_for("dashboard"))


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(debug=True)