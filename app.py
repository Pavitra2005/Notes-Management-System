from flask import Flask, redirect, render_template, request, session, url_for
import random
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import bcrypt
from database import db  
from mail import send_email

app = Flask(__name__)

app.secret_key = "notes@22"

s = URLSafeTimedSerializer(app.secret_key)






# =========================================================
# OTP
# =========================================================

def generate_otp():
    return str(random.randint(100000,999999))



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
            if send_email(email,'OTP Verification',f"Hello {session['uname']}, your OTP:{session['otp']}"):
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

@app.route("/forgotpassword",methods=["GET","POST"])
def forgotpassword():
    if request.method=="POST":
        email=request.form.get("email")
        cursor=db.cursor()
        cursor.execute("SELECT username FROM users WHERE email=%s",(email,))
        user=cursor.fetchone()
        if user:
            session['email']=email
            token=s.dumps(email, salt='password-reset-salt')
            reset_url=url_for('resetpassword',token=token, _external=True)
            send_email(email,'Password Reset Request',f'Click the link to reset your password:{reset_url}\n\nthis link will expire in 1 hour')
            return render_template("forgotpassword.html",info=" link sent  to your email,please check")
        return render_template("forgotpassword.html",info="Email is not registered")
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
        if newpassword==confirmpassword:
                email=session.get('email')
                hashed_password=bcrypt.hashpw(newpassword.encode("utf-8"),bcrypt.gensalt()).decode("utf-8")

                if email:
                    cursor=db.cursor()
                    cursor.execute("UPDATE users SET password=%s WHERE email=%s",(hashed_password,email))
                    db.commit()
                    session.pop('email',None)
                    return redirect(url_for("login"))
        else:           
            return render_template("resetpassword.html", info="Passwords do not match")
    return render_template('resetpassword.html')


#===================
#Dashboard
#===================

@app.route("/dashboard")
def dashboard():
    if 'Verified Login' in session and 'user_id' in session:
        user_id=session['user_id']
        cursor=db.cursor(dictionary=True)
        cursor.execute("select * from notes where user_id=%s order by created_at desc",(user_id,))
        notes=cursor.fetchall()
        cursor.close()
        return render_template('dashboard.html',username=session['uname'],notes=notes)
    return redirect(url_for('login'))

@app.route('/createnote',methods=['POST'])
def create_note():
    if 'user_id' in session:
        content=request.form.get('content')
        user_id=session['user_id']
        cursor=db.cursor()
        cursor.execute("INSERT INTO notes(user_id,content) VALUES (%s,%s)", (user_id,content))
        db.commit()
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/deletenote/<int:note_id>')
def delete_note(note_id):
    if 'user_id' in session:
        cursor=db.cursor()
        cursor.execute("DELETE FROM notes WHERE id=%s AND user_id=%s",(note_id, session['user_id']))
        db.commit()
    return redirect(url_for('dashboard'))

@app.route('/editnote/<int:note_id>',methods=['GET','POST'])
def edit_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    cursor=db.cursor(dictionary=True)
    if request.method=='POST':
        new_content=request.form.get('content')
        cursor.execute("UPDATE notes SET content=%s WHERE id=%s AND user_id=%s", (new_content,note_id,session['user_id']))
        db.commit()
        return redirect(url_for('dashboard'))
    else:
        cursor.execute("SELECT * FROM notes WHERE id=%s AND user_id=%s",(note_id,session['user_id']))
        note=cursor.fetchone()
        cursor.close()
        if note:
            return render_template('editnote.html',note=note)
    return redirect(url_for('dashboard'))


#================
#Logout
#================

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
    

