from werkzeug.security import generate_password_hash
from pymongo import MongoClient

# Connect to MongoDB - update URI as needed
client = MongoClient("mongodb://localhost:27017/")
db = client.userdb
users = db.users

admin_email = "admin@example.com"
admin_password = "adm!n_!0E"  # your desired admin password
admin_username = "admin"

# Check if admin user already exists, remove if yes
users.delete_many({"email": admin_email})

# Insert admin user with hashed password
hashed_password = generate_password_hash(admin_password)
users.insert_one({
    "username": admin_username,
    "email": admin_email,
    "password": hashed_password,
    "role": "admin"
})

print("Admin user created with email:", admin_email)

