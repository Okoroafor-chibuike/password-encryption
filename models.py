from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    bvn = db.Column(db.LargeBinary, nullable=False)          # Encrypted
    card_number = db.Column(db.LargeBinary, nullable=False)   # Encrypted
    pin = db.Column(db.LargeBinary, nullable=False)           # Encrypted
    is_admin = db.Column(db.Boolean, default=False)  