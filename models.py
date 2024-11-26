from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False) 
    full_name = db.Column(db.String(120), nullable=False) 

    def __init__(self, email, password, full_name):
        self.email = email
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.full_name = full_name