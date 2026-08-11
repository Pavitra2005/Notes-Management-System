from flask import Flask, redirect, render_template, request, session, url_for
import random
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import bcrypt
from database import db  

app = Flask(__name__)

app.secret_key = "notes@22"
s = URLSafeTimedSerializer(app.secret_key)



# =========================================================
# MAIL CONFIGURATION
# =========================================================

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config['MAIL_USERNAME'] = 'upavitra2005@gmail.com'
app.config['MAIL_PASSWORD'] = 'xhvr quwi ycux oqxq'
app.config['MAIL_DEFAULT_SENDER'] = 'upavitra2005@gmail.com'


mail = Mail(app)


# =========================================================
# OTP
# =========================================================

def generate_otp():
    return str(random.randint(100000,999999))

def send_otp_email(name,email,otp):
    try:
        msg=Message("OTP VERIFICATION", recipients=[email])
        msg.body=f"""
        Hello {name}, 
        Your OTP is: {otp}
        Thank You.
        """

        mail.send(msg)
        return True
    
    except Exception as e:
        print(e)
        return False


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():
    return redirect("/login")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form.get("email")
        password=request.form.get("password")
        cursor=db.cursor()
        cursor.execute("SELECT id,username,password FROM users WHERE email=%s",(email,))
        user=cursor.fetchone()
        
        if user and bcrypt.checkpw(password.encode("utf-8"),user[2].encode("utf-8")):
            session["uname"]=user[1]
            session["user_id"]=user[0]
            session["otp"]=generate_otp()
            if send_otp_email(session["uname"],email,session["otp"]):
                return redirect("verify")
            else:
              return render_template("login.html",info="Unable to send the otp")
        else:
            return render_template("login.html",info="Invalid login")
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
        # Hash password
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        cursor=db.cursor()
        cursor.execute("SELECT username FROM users WHERE email=%s",(email,))
        user=cursor.fetchone()

        if user:
            return render_template('register.html',info='Email already registered')
        cursor.execute("Insert into users(username,email,password) values (%s,%s,%s)",
                       (username,email,hashed_password))
        db.commit()
        return redirect(url_for('login'))

    return render_template("register.html")

#=====================
#OTP VERIFICATION
#=====================

@app.route("/verify", methods=["GET","POST"])
def verify():
    if request.method=="POST":
        entered_otp=request.form.get("otp")
        if entered_otp == session["otp"]:
            session.pop("otp",None)
            session["Verified Login"]=True
            return redirect(url_for("dashboard"))
        else: 
            return render_template("verify.html", info="Enter the correct otp")

    return render_template("verify.html")


#=====================
#Forgot Password
#=====================

@app.route("/forgotpassword" , methods=["GET","POST"])
def forgotpassword():

    if request.method=="POST":

        email=request.form.get("email")


        if user:

            session["email"]=email

            token=s.dumps(email, salt="password-reset-salt")

            reset_url=url_for(
                "resetpassword",
                token=token,
                _external=True
            )

            try:
                msg=Message(
                    "password Reset Request",
                    recipients=[email]
                )

                msg.body=f"""
Hello {user['username']},
Click the link below to reset your password
{reset_url}
This link will expire in 1 hour.
"""

                mail.send(msg)

            except Exception as e:
                print(e)
                return render_template(
                    "forgotpassword.html",
                    info="Unable to send the email."
                )
        return render_template(
            "forgotpassword.html",
            info="Email is not registered"
        )

    return render_template("forgotpassword.html")

#========================
#Reset Password
#========================

@app.route("/resetpassword/<token>", methods=["GET","POST"])
def resetpassword(token):
    try:
        email=s.loads(token,salt="password-reset-salt", max_age=3600)
    except SignatureExpired:
        return render_template("forgotpassword.html", info="Reset link expired.")
    except Exception:
        return render_template("forgotpassword.html", info="Invalid reset link")


    if request.method=="POST":

        newpassword=request.form.get("newpassword")
        confirmpassword=request.form.get("confirmpassword")

        if newpassword!=confirmpassword:

            return render_template(
                "resetpassword.html",
                info="password do not match"
            )


        for user in data["users"]:

            if user["email"]==email:

                hashed_password=bcrypt.hashpw(
                    newpassword.encode("utf-8"),
                    bcrypt.gensalt()
                ).decode("utf-8")

                user["password"]=hashed_password


                session.pop("email",None)

                return redirect(url_for("login"))
            
    return render_template("resetpassword.html")

#===================
#Dashboard
#===================

@app.route("/dashboard")
def dashboard():
    return redirect("/login")

#Logout

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
    

