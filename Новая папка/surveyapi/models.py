from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    

    def __init__(self, login, password):
        self.login = login
        self.password = generate_password_hash(password, method='sha256')

    @classmethod
    def authenticate(cls, **kwargs):
        login = kwargs.get('login')
        password = kwargs.get('password')
        
        if not email or not password:
            return None

        user = cls.query.filter_by(login=login).first()
        if not user or not check_password_hash(user.password, password):
            return None

        return user