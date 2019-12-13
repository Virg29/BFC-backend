from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import hashlib

db = SQLAlchemy()
def check_password_hash(password1,password2):
    h = hashlib.new('sha256')
    h.update(password2.encode('utf-8'))
    if(h.hexdigest()==password1):
        return(True)
    return(False)
def create_password_hash(password):
    h = hashlib.new('sha256')
    h.update(password.encode('utf-8'))
    return(h.hexdigest())
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    

    def __init__(self, login, password):
        self.login = login
        self.password = create_password_hash(password)
    @classmethod
    def authenticate(cls, **kwargs):
        login = kwargs.get('login')
        password = kwargs.get('password')
        
        if not login or not password:
            return False

        user = cls.query.filter_by(login=login).first()
        if not user or not check_password_hash(user.password, password):
            return False

        return user