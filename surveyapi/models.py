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
    def authenticate(cls, login, password):
        
        if not login or not password:
            return False
        #print(login)
        user = User.query.filter_by(login=login).all()
        #print(user[0].login)
        if len(user)!=1 or check_password_hash(user[0].password, password)==False:
            return False
        user = user[0]
        return user
class Post(db.Model):
    __tablename__='posts'

    id=db.Column(db.Integer,primary_key=True)
    fromuser=db.Column(db.Integer,nullable=False)
    title=db.Column(db.String(150),nullable=False)
    price=db.Column(db.Integer,nullable=False)
    alreadyhave=db.Column(db.Integer, default=0)
    latc=db.Column(db.String(20),nullable=False)
    longc=db.Column(db.String(20),nullable=False)
    files=db.Column(db.String(500),nullable=False)
    addres=db.Column(db.String(150),nullable=False)
    tags=db.Column(db.String(150),default="")