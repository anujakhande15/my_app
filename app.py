from flask import Flask,render_template,request,redirect,flash,url_for,session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import time
from datetime import timedelta


import uuid
import os
from datetime import datetime
from flask import request
import random









app = Flask(__name__)
app.secret_key = "mysecretkey"


app.permanent_session_lifetime = timedelta(minutes=1)


app.config["UPLOAD_FOLDER"] = "static/uploads"

app.config["SQLALCHEMY_DATABASE_URI"]='sqlite:///data.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
db = SQLAlchemy(app)









app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"]=587
app.config["MAIL_USE_TLS"]=True
app.config["MAIL_USERNAME"]='anukhande15@gmail.com'
app.config['MAIL_PASSWORD']='fazjdztoiijaoxgp'


mail = Mail(app)

@app.before_request
def session_timeout():
    session.permanent = True
    session.modified = True

    if "user_id" in session:
        last_activity = session.get("last_activity")

        if last_activity:
            now = time.time()
            diff = now - last_activity
            if diff > app.permanent_session_lifetime.total_seconds():
                session.clear()
                flash("session is expried! Try again",'warning')
                return redirect("/login")
        session["last_activity"] = time.time()











class User(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(50),unique=True,nullable=False)
    email = db.Column(db.String(100),unique=True,nullable=False)
    password = db.Column(db.String(200),nullable=False)    
    reset_token = db.Column(db.String(100), nullable=True)  
    profile_images = db.Column(db.String(200),default="default.png")
    role = db.Column(db.String(20), default='user')
    status = db.Column(db.String(10), default='active')
    last_login = db.Column(db.String(100),nullable=True)
    last_login_ip = db.Column(db.String(100),nullable=True)
    device = db.Column(db.String(50))
    os = db.Column(db.String(50))
    browser = db.Column(db.String)  



class ContactEditHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contact_id = db.Column(db.Integer)
    edited_by = db.Column(db.Integer)  
    old_name = db.Column(db.String(50))
    old_email = db.Column(db.String(100))
    old_message = db.Column(db.String(200))
    edited_at = db.Column(db.DateTime, default=datetime.utcnow)



     
class PasswordOTP(db.Model): 
   id = db.Column(db.Integer, primary_key=True) 
   email = db.Column(db.String(200), nullable=False) 
   otp = db.Column(db.String(10), nullable=False) 
   reated_at = db.Column(db.DateTime, default=datetime.utcnow)


     

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id'), nullable=False)

    user = db.relationship("User", backref="favorites")
    contact = db.relationship("Contact", backref="favorited_by")




class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device = db.Column(db.String(50))
    os = db.Column(db.String(50))
    browser = db.Column(db.String(50))
    ip = db.Column(db.String(100))
    login_time = db.Column(db.String(100))

    user = db.relationship("User", backref="logins")


class FailedLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    browser = db.Column(db.String(50))
    device = db.Column(db.String(50))
    os = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True)
    reason = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())



class Contact(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(100))
    message = db.Column(db.String(200))
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)





class Notification(db.Model):   
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    message = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def create_notification(user_id, message):
    note = Notification(user_id=user_id, message=message)
    db.session.add(note)
    db.session.commit()

class ActiveSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),    
        nullable=False
    )

    ip_address = db.Column(db.String(100))
    device = db.Column(db.String(50))
    browser = db.Column(db.String(50))
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    user = db.relationship("User", backref="active_sessions")








@app.route("/")
def home():
    if "user_id" not in session:
        flash("Please loging to access app","warning")
        return redirect("/login")
    
    return render_template("home.html")


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        uname = request.form['username']
        uemail = request.form["email"]
        upass = request.form['password']

        existing_user = User.query.filter_by(email=uemail).first()
        if existing_user:
            flash("Email already exists! Please try logging in", "warning")
            return redirect("/login")
        
        hash_pass = generate_password_hash(upass)
        new_data = User(username=uname, email=uemail, password=hash_pass)
        db.session.add(new_data)
        db.session.commit()
        flash("Account created successfully! Please login", "success")
        return redirect("/login")
    
    return render_template("signup.html")



@app.route("/login", methods=['GET', 'POST'])
def login():
    ip_addr = request.remote_addr
    blocked = BlockedIP.query.filter_by(ip_address=ip_addr).first()

    if blocked:
        flash("Your IP is temporarily blocked due to suspicious activity!", "danger")
        return redirect("/login")
    


    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if not user:
            
            import platform
            from user_agents import parse

            ua_string = request.headers.get('User-Agent')
            user_agent = parse(ua_string)
            device_type = "Mobile" if user_agent.is_mobile else "Desktop"
            browser = user_agent.browser.family
            os_name = user_agent.os.family
            ip_addr = request.remote_addr

            failed = FailedLogin(
                email=email,
                ip_address=ip_addr,
                browser=browser,
                device=device_type,
                os=os_name
            )
            db.session.add(failed)
            db.session.commit()

            flash("Invalid email or password", "warning")
            return redirect("/login")

        if user.status == 'blocked':
            flash("Your account is blocked. Contact admin.", "danger")
            return redirect("/login")
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['last_activity'] = time.time()
            session['username'] = user.username
            session['role'] = user.role
            create_notification(user.id, "You logged in successfully")   


            user.last_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            user.last_login_ip = request.remote_addr

            ua_string = request.headers.get('User-Agent')

            if 'Mobile' in ua_string:
                user.device = 'Mobile'
            else:
                user.device = 'Desktop'
            
            if 'Windows' in ua_string:
                user.os = 'Windows'
            elif 'Mac' in ua_string:
                user.os = 'MacOS'
            elif 'Linux' in ua_string:
                user.os = 'Linux'
            elif "Android" in ua_string:
                user.os = 'Android'
            elif 'iPhone' in ua_string:
                user.os = 'iPhone / iOS'
            else:
                user.os = 'Unknown'

            if 'Chrome' in ua_string:
                user.browser = 'Chrome'
            elif 'Firefox' in ua_string:
                user.browser = 'Firefox'
            elif 'Safari' in ua_string and 'Chrome' not in ua_string:
                user.browser = 'Safari'
            elif 'Edge' in ua_string:
                user.browser = 'Edge'
            else:
                user.browser = 'Unknown'
            
            db.session.commit()

            history = LoginHistory(
                user_id = user.id,
                device = user.device,
                os = user.os,
                browser = user.browser,
                ip = request.remote_addr,
                login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            db.session.add(history)
            db.session.commit()

            active_session = ActiveSession(
                user_id=user.id,
                ip_address=request.remote_addr,
                device=user.device,
                browser=user.browser
            )
            db.session.add(active_session)
            db.session.commit()

            session["active_session_id"] = active_session.id

            flash(f"Welcome {user.username}", "success")
            return redirect("/")
        else:
            
            import platform
            from user_agents import parse

            ua_string = request.headers.get('User-Agent')
            user_agent = parse(ua_string)
            device_type = "Mobile" if user_agent.is_mobile else "Desktop"
            browser = user_agent.browser.family
            os_name = user_agent.os.family
            ip_addr = request.remote_addr

            failed = FailedLogin(
                email=email,
                ip_address=ip_addr,
                browser=browser,
                device=device_type,
                os=os_name
            )
            db.session.add(failed)
            db.session.commit()

            flash("Invalid email or password", "warning")
            return redirect("/login")

    return render_template("login.html")

@app.route("/submit",methods=['POST'])
def submit():

    if "user_id" not in session:
        flash("access to login required","warning")
        return redirect("/login")
    

    name = request.form["username"]
    email = request.form["useremail"]
    message = request.form["usermsg"]

    new_data = Contact(name=name,email=email,message=message)
    db.session.add(new_data)
    db.session.commit()

    msg = Message("New Contact From Submission",
                  sender='anukhande15@gmail.com',
                  recipients=[email])
    msg.body = f"Hello {name},\n\nThank you for contacing us!\n\nYour Message : {message}\n\nWe'll get back to you seen."
    mail.send(msg)

    flash("Data Added successfully !& email send","success")
    return redirect("/show")
    


    


@app.route("/show")
def show():

    if "user_id" not in session:
        flash("Plase login to view data","warning")
        return redirect("/login")

    query = request.args.get("query")

    if query:
        contacts = Contact.query.filter(
            (Contact.name.contains(query) | Contact.email.contains(query)) &
            (Contact.is_deleted == False)
        ).all()
    else:
        contacts = Contact.query.filter_by(is_deleted=False).all()

    return render_template("show.html",contacts=contacts)



















@app.route("/edit/<int:id>")
def edit(id):
    contact = Contact.query.get_or_404(id)
    return render_template("edit.html",contact=contact)





@app.route("/update/<int:id>",methods=['POST'])
def update(id):
    contact = Contact.query.get_or_404(id)


    history = ContactEditHistory(
        contact_id=contact.id,
        edited_by=session.get("user_id"),
        old_name=contact.name,
        old_email=contact.email,
        old_message=contact.message
    )
    db.session.add(history)

    contact.name = request.form["username"]
    contact.email = request.form["useremail"]
    contact.message = request.form["usermsg"]
    db.session.commit()
    flash("Data update Successfully !","info")
    return redirect("/show")





@app.route("/delete/<int:id>")
def delete(id):
    contact = Contact.query.get_or_404(id)

    contact.is_deleted = True
    contact.deleted_at = datetime.utcnow()

    db.session.commit()
    flash("Contact moved to Recycle Bin","warning")
    return redirect("/show")






@app.route("/forgot", methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = str(uuid.uuid4())  
            user.reset_token = token  
            db.session.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            print(" RESET LINK:", reset_link) 

            msg = Message("Password Reset Request",
                          sender='anukhande15@gmail.com',
                          recipients=[email])
            msg.body = f"Click the link below to reset your password:\n{reset_link}"
            mail.send(msg)

            flash("Password reset link sent to your email!", "info")
            return redirect("/login")
        else:
            flash("Email not found!", "danger")
    return render_template("forgot.html")



@app.route("/reset/<token>", methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()  

    if not user:
        flash("Invalid or expired reset link!", "danger")
        return redirect("/forgot")

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm']

        if new_password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(request.url)

        user.password = generate_password_hash(new_password)
        user.reset_token = None  
        db.session.commit()
        


        flash("Password reset successful! Please login.", "success")
        return redirect("/login")

    return render_template("reset.html", token=token)



@app.route("/verify_otp", methods=['GET', 'POST'])
def verify_otp():
    email = session.get("reset_email")

    if not email:
        flash("Session expired! Try again.", "danger")
        return redirect("/forgot")

    if request.method == "POST":
        user_otp = request.form["otp"]

        otp_entry = PasswordOTP.query.filter_by(email=email).order_by(PasswordOTP.id.desc()).first()

        if not otp_entry or otp_entry.otp != user_otp:
            flash("Invalid OTP!", "danger")
            return redirect("/verify_otp")

        flash("OTP verified successfully!", "success")
        return redirect(f"/reset_otp_password")

    return render_template("verify_otp.html", email=email)




@app.route("/send_otp", methods=['POST'])
def send_otp():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()

    if not user:
        flash("Email not registered!", "danger")
        return redirect("/forgot")

    otp = str(random.randint(100000, 999999))

    otp_entry = PasswordOTP(email=email, otp=otp)
    db.session.add(otp_entry)
    db.session.commit()

    session["reset_email"] = email

    msg = Message("Your Password Reset OTP",
                  sender='anukhande15@gmail.com',
                  recipients=['anukhande15@gmail.com'])
    msg.body = f"Your OTP for password reset is: {otp}"
    mail.send(msg)

    flash("OTP sent to your email!", "success")
    return redirect("/verify_otp")




@app.route("/reset_otp_password", methods=['GET', 'POST'])
def reset_otp_password():
    email = session.get("reset_email")

    if not email:
        flash("Session expired!", "danger")
        return redirect("/forgot")

    if request.method == 'POST':
        new = request.form['password']
        confirm = request.form['confirm']

        if new != confirm:
            flash("Passwords do not match!", "danger")
            return redirect("/reset_otp_password")

        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(confirm)
        db.session.commit()
        


        session.pop("reset_email")
        flash("Password reset successful!", "success")
        return redirect("/login")

    return render_template("reset_password_otp.html")


@app.route("/favorite/<int:contact_id>")
def favorite(contact_id):
    if "user_id" not in session:
        flash("Login required", "warning")
        return redirect("/login")
    
    user_id = session["user_id"]
    exists = Favorite.query.filter_by(user_id=user_id, contact_id=contact_id).first()

    if exists:
        db.session.delete(exists)
        db.session.commit()
        flash("Removed from favorites", "info")
    else:
        new_fav = Favorite(user_id=user_id, contact_id=contact_id)
        db.session.add(new_fav)
        db.session.commit()
        flash("Added to favorites", "success")

    return redirect("/show")




@app.route("/favorites")
def favorites():
    if "user_id" not in session:
        flash("Login required", "warning")
        return redirect("/login")
    
    user_id = session["user_id"]
    favorites = Favorite.query.filter_by(user_id=user_id).all()
    return render_template("favorites.html", favorites=favorites)




@app.route("/profile")
def profile():
    if "user_id" not in session:
        flash("Plase login first","warning")
        return redirect("/login")
    
    user = User.query.get(session['user_id'])
    return render_template("profile.html",user=user)

@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        flash("Please login first!", "warning")
        return redirect("/login")

    user = User.query.get(session["user_id"])

    if request.method == "POST":
        user.name = request.form["name"]
        user.email = request.form["email"]

        if "profile_image" in request.files:
            file = request.files["profile_image"]
            if file.filename != "":
                filename = secure_filename(file.filename)
                upload_folder = app.config["UPLOAD_FOLDER"]
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)
                
                filepath = os.path.join(upload_folder,filename)
                file.save(filepath)
                user.profile_images = filename

        db.session.commit()
        flash("Profile Updated Successfully!", "success")
        return redirect("/profile")

    return render_template("edit_profile.html", user=user)








@app.route("/change-image",methods=['GET','POST'])
def change_image():
    if "user_id" not in session:
        flash("login required",'warning')
        return redirect("/login")
    
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        if "profile_image" not in request.files:
            flash("Not file not slected",'danger')
            return redirect("/change-image")
        
        file = request.files["profile_image"]   

        if file.filename == "":
            flash("Plase select image file",'danger')    
            return redirect("/change-image")
        
        filename = secure_filename(file.filename)
        folder = app.config["UPLOAD_FOLDER"]

        if not os.path.exists(folder):
            os.makedirs(folder)

        path = os.path.join(folder,filename)
        file.save(path)

        user.profile_images = filename
        db.session.commit()

        flash("Profile photo update successfully","success")
        return redirect("/profile")
    
    return render_template("change_profile_picture.html",user=user)

















@app.route("/change-password",methods=['GET',"POST"])
def change_password():
    if "user_id" not in session:
        flash("login required",'warning')
        return redirect("/login")
    
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        old_pass = request.form['old']
        new_pass = request.form['new']
        confirm_pass = request.form['confirm']

        if not check_password_hash(user.password,old_pass):
            flash("old password is incorrect",'danger')
            return redirect("/change-password")
        
        if new_pass != confirm_pass:
            flash("New password do not match",'danger')
            return redirect("/change-password")
        
        user.password = generate_password_hash(new_pass)
        db.session.commit()
        create_notification(user.id, "Your password was changed")   # ✅


        flash("Password changed successfully!",'success')
        return redirect("/profile")
    return render_template("change_password.html",user=user)











@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please login First")
        return redirect("/login")
    



    user = User.query.get(session["user_id"])

    if user.role != 'admin':
        flash("Access Denied ! this admin session","danger")
        return redirect("/")

    
    total_users = User.query.count()
    total_contacts = Contact.query.count()


    from datetime import date
    active_users = User.query.filter_by(status='active').count()
    blocked_users = User.query.filter_by(status='blocked').count()

    today = date.today().strftime("%Y-%m-%d")
    todays_logins = User.query.filter(User.last_login.like(f"{today}%")).count()

    active_users = User.query.filter_by(status="active").count()
    blocked_users = User.query.filter_by(status="blocked").count()

    from datetime import date
    today = date.today().strftime("%Y-%m-%d")
    todays_logins = User.query.filter(User.last_login.like(f"{today}%")).count()
    


    return render_template("dashboard.html",
                           total_users=total_users,
                           total_contacts=total_contacts,
                           logged_user=user,
                           active_users=active_users,
                           blocked_users=blocked_users,
                           todays_logins=todays_logins)


@app.route("/manage-users")
def manage_users():
    if "user_id" not in session:
        flash("login required","warning")
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("Access Denied!Admin only",'danger')
        return redirect("/")
    
    users = User.query.all()
    return render_template("manage_users.html",users=users)



@app.route("/edit-user/<int:id>",methods=['GET','POST'])
def edit_user(id):
    if "user_id" not in session:
        flash("login required",'warning')
        return redirect("/login")
    
    admin = User.query.get(session["user_id"])

    if admin.role != 'admin':
        flash("Access Denied",'danger')
        return redirect("/")
    
    user = User.query.get_or_404(id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']

        db.session.commit()
        

        flash("User Update Successfully",'success')
        return redirect("/manage-users")
    return  render_template("edit_user.html",user=user)

@app.route("/admin/reset-password/<int:id>",methods=['GET','POST'])
def admin_reset_password(id):
    if "user_id" not in session:
        flash("login required",'warning')
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("Access Denied",'danger')
        return redirect("/")
    
    user = User.query.get_or_404(id)

    if request.method == 'POST':
        New_password = request.form['password']

        hashed = generate_password_hash(New_password)

        user.password = hashed
        db.session.commit()
    

        
        
        flash("User Password Updated",'success')
        return redirect("/manage-users")
    return render_template("admin_reset_password.html",user=user)
        



@app.route("/delete-user/<int:id>")
def delete_user(id):
    if "user_id" not in session:
        flash("login required","warning")
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("Access denied!admin only","danger")
        return redirect("/")
    
    user = User.query.get_or_404(id)

    if user.role == 'admin':
        flash("Admin cannot be deleted","danger")
        return redirect("/manage-users")
    
    LoginHistory.query.filter_by(user_id=user.id).delete()
    
    try:
        if user.profile_images and user.profile_images != "default.png":
            path = os.path.join(app.config["UPLOAD_FOLDER"], user.profile_images)
            if os.path.exists(path):
                os.remove(path)
    except Exception:
        pass

    

    db.session.delete(user)
    db.session.commit()

    flash("User delete successfully","success")
    return redirect("/manage-users")

@app.route("/admin/change-user-photo/<int:id>",methods=['GET','POST'])
def admin_change_user_photo(id):
    if "user_id" not in session:
        flash("login required",'warning')
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("Access Denied",'danger')
        return redirect("/")
    
    user = User.query.get_or_404(id)

    if request.method == 'POST':
        if "photo" not in request.files:
            flash("file Not Selected",'danger')
            return redirect(request.url)
        
        file = request.files["photo"]

        if file.filename == '':
            flash("File not selected",'danger')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        folder = app.config['UPLOAD_FOLDER']

        if not os.path.exists(folder):
            os.makedirs(folder)

        path = os.path.join(folder,filename)
        file.save(path)

        user.profile_images = filename
        db.session.commit()
        

        create_notification(user.id, "Your profile photo was updated by admin")

        flash("User Profile updated by admin",'success')
        return redirect("/manage-users")
    return render_template("admin_change_user_photo.html",user=user)



@app.route("/admin/delete-user-photo/<int:id>")
def admin_delete_user_photo(id):
    if 'user_id' not in session:
        flash("login required",'warning')
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("Access Denied",'danger')
        return redirect("/")
    
    user = User.query.get_or_404(id)

    if user.profile_images:
        folder = app.config['UPLOAD_FOLDER']
        path = os.path.join(folder,user.profile_images)

        if os.path.exists(path):
            os.remove(path)
        
        user.profile_images = None
        db.session.commit()
        

        create_notification(user.id, "Your profile photo was deleted by admin")


        flash("user Profile Photo Deleted",'success')
    else:
        flash("User has not profile photo",'info')

    return redirect("/manage-users")





@app.route("/manage-contacts")
def manage_contacts():
    if "user_id" not in session:
        flash("login required","warning")
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("Access Denied ! Admin only",'danger')
        return redirect("/")
    
    contacts = Contact.query.order_by(Contact.id.desc()).all()
    return render_template("manage_contacts.html",contacts=contacts)




@app.route("/admin/login-history")
def admin_login_history():
    if "user_id" not in session:
        flash("Login required", "warning")
        return redirect("/login")

    admin = User.query.get(session['user_id'])
    if not admin or admin.role != 'admin':
        flash("Access Denied", "danger")
        return redirect("/")
    
    browser = request.args.get('browser')
    device = request.args.get("device")
    os_name = request.args.get("os")

    history = LoginHistory.query

    if browser:
        history = history.filter_by(browser=browser)
    
    if device:
        history = history.filter_by(device=device)

    if os_name:
        history = history.filter_by(os=os_name)

    history = history.order_by(LoginHistory.id.desc()).all()
    return render_template("admin_login_history.html", history=history)





@app.route("/user-login-history/<int:id>")
def user_login_history(id):
    if "user_id" not in session:
        flash("login required",'warning')
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("Access Denied",'danger')
        return redirect("/")
    
    user = User.query.get_or_404(id)

    logs = LoginHistory.query.filter_by(user_id=id).order_by(LoginHistory.id.desc()).all()

    return render_template("user_login_history.html",user=user,logs=logs)














@app.route("/delete-contact/<int:id>")
def delete_contact(id):
    if "user_id" not in session:
        flash("login required","warning")
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("Access Denied! admin only",'danger')
        return redirect("/")
    
    contact = Contact.query.get_or_404(id)

    db.session.delete(contact)
    db.session.commit()
    


    


    flash("Contact message delete successfully","success")
    return redirect("/manage-contacts")


@app.route("/failed-logins")
def failed_logins():
    if "user_id" not in session:
        flash("login required",'warning')
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("access denied",'danger')
        return redirect("/")
    
    attempts = FailedLogin.query.order_by(FailedLogin.id.desc()).all()
    return render_template("failed_logins.html",attempts=attempts)



@app.route("/block-ip/<ip>")
def block_ip(ip):
    if "user_id" not in session:
        flash("Login required", "warning")
        return redirect("/login")

    admin = User.query.get(session["user_id"])
    if not admin or admin.role != "admin":
        flash("Access Denied", "danger")
        return redirect("/")

    exists = BlockedIP.query.filter_by(ip_address=ip).first()
    if exists:
        flash("This IP is already blocked!", "info")
        return redirect("/failed-logins")

    new_ip = BlockedIP(ip_address=ip)
    db.session.add(new_ip)
    db.session.commit()

    
    


    flash("IP Blocked Successfully!", "success")
    return redirect("/failed-logins")


@app.route("/unblock-ip/<int:id>")
def unblock_ip(id):
    if "user_id" not in session:
        flash("Login required", "warning")
        return redirect("/login")

    admin = User.query.get(session["user_id"])
    if not admin or admin.role != "admin":
        flash("Access Denied", "danger")
        return redirect("/")

    ip_entry = BlockedIP.query.get_or_404(id)
    db.session.delete(ip_entry)
    db.session.commit()

    






    flash("IP Unblocked Successfully", "success")
    return redirect("/blocked-ips")



@app.route("/blocked-ips")
def blocked_ips():
    if "user_id" not in session:
        flash("Login required", "warning")
        return redirect("/login")

    admin = User.query.get(session["user_id"])
    if not admin or admin.role != "admin":
        flash("Access Denied", "danger")
        return redirect("/")
    
    


    ips = BlockedIP.query.order_by(BlockedIP.id.desc()).all()
    return render_template("blocked_ips.html", ips=ips)






@app.route("/block-user/<int:id>")
def block_user(id):
    if "user_id" not in session:
        flash("login required","warning")
        return redirect("/login")
    
    admin = User.query.get(session["user_id"])

    if admin.role != 'admin':
        flash("Access Denied",'danger')
        return redirect("/")
    
    user = User.query.get_or_404(id)
    user.status = 'blocked' 
    db.session.commit()


    
    create_notification(user.id, "Your account has been blocked by admin")  


    flash("User has been block",'warning')
    return redirect("/manage-users")




@app.route("/unblock-user/<int:id>")
def unblock_user(id):
    if "user_id" not in session:
        flash("login required",'warning')
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("Access Denied",'danger')
        return redirect("/")
    
    user = User.query.get_or_404(id)
    user.status = 'active'
    db.session.commit()
    

    create_notification(user.id, "Your account has been unblocked")  

    flash("User has been unblock",'success')
    return redirect("/manage-users")


@app.route("/notifications")   
def notifications():
    if "user_id" not in session:
        return redirect("/login")

    notes = Notification.query.filter_by(
        user_id=session["user_id"]
    ).order_by(Notification.created_at.desc()).all()

    return render_template("notifications.html", notes=notes)

@app.route("/admin/active-sessions")
def admin_active_sessions():
    if "user_id" not in session:
        flash("login required",'warning')
        return redirect("/login")
    
    admin = User.query.get(session["user_id"])

    if admin.role != "admin":
        flash("Access Denied",'danger')
        return redirect("/")
    
    sessions = ActiveSession.query.order_by(ActiveSession.id.desc()).all()
    return render_template("admin_active_sessions.html",sessions=sessions)



@app.route("/admin/force-logout/<int:id>")
def admin_force_logout(id):
    if "user_id" not in session:
        flash("login required",'warning')
        return redirect("/login")
    admin = User.query.get(session["user_id"])

    if admin.role != "admin":
        flash("Access Denied",'danger')
        return redirect("/")
    
    s = ActiveSession.query.get_or_404(id)
    s.is_active = False
    db.session.commit()

    flash("User Logout Forcefully",'warning')
    return redirect("/admin/active-sessions")

@app.route("/admin/login-heatmap")
def login_heatmap():
    if "user_id" not in session:
        return redirect("/login")

    admin = User.query.get(session["user_id"])
    if admin.role != "admin":
        return redirect("/")

    from sqlalchemy import func

    data = db.session.query(
        func.strftime('%H', FailedLogin.timestamp).label("hour"),
        FailedLogin.ip_address,
        FailedLogin.device,
        FailedLogin.browser,
        func.count(FailedLogin.id).label("count")
    ).group_by("hour", FailedLogin.ip_address, FailedLogin.device, FailedLogin.browser
    ).order_by(func.count(FailedLogin.id).desc()).all()

    return render_template("login_heatmap.html", data=data)


@app.route("/admin/contact-history/<int:id>")
def admin_contact_history(id):
    if "user_id" not in session:
        flash("Login Required","warning")
        return redirect("/login")
    
    admin = User.query.get(session["user_id"])

    if admin.role != 'admin':
        flash("Access Denied",'danger')
        return redirect("/")
    
    history = ContactEditHistory.query.filter_by(contact_id=id).order_by(ContactEditHistory.edited_at.desc()).all()

    return render_template("contact_history.html",history=history)



@app.route("/admin/restore-contact/<int:history_id>")
def admin_restore_contact(history_id):
    if "user_id" not in session:
        flash("Login required",'waning')
        return redirect("/login")
    
    admin = User.query.get(session["user_id"])

    if admin.role != "admin":
        flash("Access Denied",'danger')
        return redirect("/")
    
    history = ContactEditHistory.query.get_or_404(history_id)
    contact = Contact.query.get_or_404(history.contact_id)

    new_history = ContactEditHistory(
        contact_id=contact.id,
        edited_by=admin.id,
        old_name=contact.name,
        old_email=contact.email,
        old_message=contact.message
    )
    db.session.add(new_history)





    contact.name = history.old_name
    contact.email = history.old_email
    contact.message = history.old_message

    db.session.commit()
    flash("Contact Restore previous version","success")
    return redirect("/admin/contact-history/" + str(contact.id))









@app.route("/admin/recycle-bin/")
def admin_recycle_bin(): 
    if "user_id" not in session:
        flash("Access Denied",'warning')
        return redirect("/login")
    
    admin = User.query.get(session['user_id'])

    if admin.role != 'admin':
        flash("Access Denied",'danger')
        return redirect("/")
    
    contacts = Contact.query.filter_by(is_deleted=True).all()
    return render_template("recycle_bin.html",contacts=contacts)






@app.route("/admin/restore-deleted-contact/<int:id>")
def admin_restore_deleted_contact(id):
    admin = User.query.get(session['user_id'])
    
    if admin.role != 'admin':
        flash("Access Denied",'danger')
        return redirect("/")
    

    contact = Contact.query.get_or_404(id)
    contact.is_deleted = False
    contact.deleted_at = None
    db.session.commit()

    flash("Contact Restore successfully",'success')
    return redirect("/admin/recycle-bin")

@app.route("/admin/permanent-delete/<int:id>")
def admin_permanent_delete(id):
    admin = User.query.get(session["user_id"])

    if admin.role != 'admin':
        flash("Access Denied",'danger')   
        return redirect("/")
    
    contact = Contact.query.get(session["user_id"])
    db.session.delete(contact)
    db.session.commit()

    flash("Contact Deleted Successfully",'danger')
    return redirect("/admin/recycle-bin")



@app.route("/logout")
def logout():
    sid = session.get("active_session_id")
    if sid:
        s = ActiveSession.query.get(sid)
        if s:
            s.is_active = False
            db.session.commit()

    session.clear()
    flash("Logged out successfully", "info")
    return redirect("/login")



if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        admin_email = "admin@gmail.com"
        admin = User.query.filter_by(email=admin_email).first()
        if not admin:
            admin_pass = generate_password_hash("admin123")
            new_admin = User(username="Admin", email=admin_email, password=admin_pass,role="admin")
            db.session.add(new_admin)
            db.session.commit()
            print("✅ Admin created (admin@gmail.com / admin123)")











    app.run(debug=True)

















