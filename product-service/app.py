from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from flask_jwt_extended import (
    JWTManager, jwt_required, get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, FloatField
from wtforms.validators import InputRequired, Length, NumberRange
from functools import wraps
import os
import logging

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')

# MongoDB Configuration
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/productdb')
mongo = PyMongo(app)
products_collection = mongo.db.products

# JWT Config
app.config["JWT_SECRET_KEY"] = "super-shared-secret"
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False  # True in production
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Enable in prod
jwt = JWTManager(app)

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200/day", "50/hour"])

# Logging setup
logging.basicConfig(level=logging.INFO, filename='admin_actions.log', format='%(asctime)s - %(message)s')

# WTForms class
class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[InputRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[InputRequired(), Length(min=2, max=255)])
    price = FloatField('Price', validators=[InputRequired(), NumberRange(min=0.01)])
    image_url = StringField('Image URL', validators=[Length(max=255)])

# Role-based access
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get('role') != 'admin':
            flash("Admins only!", "danger")
            return redirect(url_for('index'))
        return fn(*args, **kwargs)
    return wrapper

# Load user info into g
@app.before_request
@jwt_required(optional=True)
def load_current_user():
    identity = get_jwt_identity()
    claims = get_jwt()
    if identity:
        g.current_user = {
            'email': identity,
            'role': claims.get('role', '')
        }
    else:
        g.current_user = None

# Home - Product Listing
@app.route('/')
def index():
    products = products_collection.find()
    return render_template("index.html", products=products)

# Add Product
@app.route('/add', methods=['GET', 'POST'], endpoint='add_product')
@admin_required
@limiter.limit("5 per minute")
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        products_collection.insert_one({
            'name': form.name.data,
            'description': form.description.data,
            'price': form.price.data,
            'image_url': form.image_url.data
        })
        logging.info(f"Admin added product: {form.name.data}")
        flash('Product added successfully!', 'success')
        return redirect('/product/manage')
    elif request.method == 'POST':
        flash('All fields are required and must be valid.', 'danger')
    return render_template("add_product.html", form=form)

# Manage Products (Admin only)
@app.route('/manage')
@admin_required
def manage_products():
    products = products_collection.find()
    return render_template("product_list.html", products=products)

# Edit Product
@app.route('/edit/<product_id>', methods=['GET', 'POST'], endpoint='edit_product')
@admin_required
@limiter.limit("5 per minute")
def edit_product(product_id):
    try:
        product = products_collection.find_one({"_id": ObjectId(product_id)})
    except Exception:
        flash("Invalid product ID.", "danger")
        return redirect('/product/manage')

    if not product:
        flash("Product not found.", "danger")
        return redirect('/product/manage')

    form = ProductForm(data=product)
    if form.validate_on_submit():
        products_collection.update_one(
            {'_id': ObjectId(product_id)},
            {'$set': {
                'name': form.name.data,
                'description': form.description.data,
                'price': form.price.data,
                'image_url': form.image_url.data
            }}
        )
        logging.info(f"Admin updated product: {product_id}")
        flash('Product updated successfully!', 'success')
        return redirect('/product/manage')
    elif request.method == 'POST':
        flash('All fields are required and must be valid.', 'danger')

    return render_template('add_product.html', form=form, product=product)

# Delete Product
@app.route('/delete/<product_id>', methods=['POST'], endpoint='delete_product')
@admin_required
@limiter.limit("5 per minute")
def delete_product(product_id):
    try:
        result = products_collection.delete_one({"_id": ObjectId(product_id)})
        if result.deleted_count:
            logging.info(f"Admin deleted product: {product_id}")
            flash('Product deleted.', 'info')
        else:
            flash('Product not found.', 'danger')
    except Exception:
        flash('Invalid product ID.', 'danger')
    return redirect('/product/manage')

# API - Get Products as JSON
@app.route('/api/products')
@jwt_required()
def get_products_api():
    products = products_collection.find()
    output = []
    for product in products:
        output.append({
            'id': str(product['_id']),
            'name': product['name'],
            'description': product['description'],
            'price': product['price'],
            'image_url': product.get('image_url', '')
        })
    return jsonify({'products': output})

# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
