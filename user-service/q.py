from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response


from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
import logging
import os

print(generate_password_hash("adm!n_!0E"))
