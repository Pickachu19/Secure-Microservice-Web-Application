from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_pymongo import PyMongo
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies, verify_jwt_in_request, get_jwt
)
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
import logging
import os
from datetime import timedelta
from functools import wraps
import re

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key"
app.config["JWT_SECRET_KEY"] = "super-shared-secret"
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://mongodb:27017/userdb')
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_SAMESITE"] = "Lax"
app.config["JWT_ACCESS_COOKIE_PATH"] = "/"
app.config["JWT_COOKIE_CSRF_PROTECT"] = True  # Set to True and enable CSRF handling for more security

jwt = JWTManager(app)
csrf = CSRFProtect(app)
mongo = PyMongo(app)
users_collection = mongo.db.users

# Logger setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --------------------------
#  MongoDB Injection Filter
# --------------------------
def is_safe_string(input_str):
    """
    Allows valid characters in emails but blocks MongoDB operators like $gt, $ne, etc.
    """
    if not isinstance(input_str, str):
        return False

    # Reject if it looks like an injection pattern (e.g. {$ne: ""}, {"$gt": ""})
    if re.search(r'\$[a-zA-Z]+', input_str):
        return False

    # Also reject braces or Mongo-like structure characters
    if any(x in input_str for x in ['{', '}', '[', ']']):
        return False

    return True

# --------------------------
# WTForms
# --------------------------
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[0-9!@#$%^&*(),.?":{}|<>])', message="Password must contain at least one number or special character.")
    ])
    confirm_password = PasswordField("Confirm Password", validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match.")
    ])
    submit = SubmitField("Register")

# --------------------------
#  Register Route
# --------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        if not is_safe_string(email):
            flash("Invalid characters detected in email.", "danger")
            return render_template("register.html", form=form)

        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            flash("Email already registered. Please log in or use a different email.", "danger")
            return render_template("register.html", form=form)

        hashed_password = generate_password_hash(form.password.data, method="pbkdf2:sha256")

        users_collection.insert_one({
            "email": email,
            "password": hashed_password,
            "role": "user"
        })

        flash("Registration successful! Please log in.", "success")
        return redirect('/user/login')

    return render_template("register.html", form=form)

# --------------------------
#  Login Route
# --------------------------
@app.route("/login", methods=["GET", "POST"])
def login_api():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        if not is_safe_string(email):
            return render_template("login.html", form=form, error="Invalid characters in email.")

        user = users_collection.find_one({"email": email})
        if user and check_password_hash(user["password"], form.password.data):
            access_token = create_access_token(
                identity=user["email"],
                additional_claims={"role": user.get("role", "user")},
                expires_delta=timedelta(hours=1)
            )
            response = make_response(
                redirect("/product/manage" if user.get("role") == "admin" else "/product/")
            )
            set_access_cookies(response, access_token)
            return response
        else:
            return render_template("login.html", form=form, error="Invalid credentials")
    return render_template("login.html", form=form)

# --------------------------
#  Logout
# --------------------------
@app.route("/logout")
def logout():
    response = make_response(redirect(url_for("login_api")))
    unset_jwt_cookies(response)
    return response

# --------------------------
# Admin Decorator
# --------------------------
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request(locations=["cookies"])
            claims = get_jwt()
            if claims.get("role") != "admin":
                flash("Admin access required.", "danger")
                return redirect(url_for("login_api"))
        except Exception:
            flash("Authentication required.", "danger")
            return redirect(url_for("login_api"))
        return fn(*args, **kwargs)
    return wrapper

# --------------------------
# Main
# --------------------------
if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, port=5000)
