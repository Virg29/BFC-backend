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
    logged = db.Column(db.BOOLEAN,default=True)

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
    prim=db.Column(db.String(150),default="")
    fromuser=db.Column(db.String(150),nullable=False)
    title=db.Column(db.String(50),default="")
    price=db.Column(db.Integer,default="")
    alreadyhave=db.Column(db.Integer, default=0)
    latc=db.Column(db.String(20),default="")
    longc=db.Column(db.String(20),default="")
    files=db.Column(db.String(1000),default="")
    addres=db.Column(db.String(150),default="")
    tags=db.Column(db.String(1000),default="")
    article=db.Column(db.String(1500),default="")
    desc=db.Column(db.String(100),default="")
    visibility=db.Column(db.BOOLEAN,default=False)
    def to_dict(self):
      return dict(id=self.id,
                  fromuser=self.fromuser,
                  prim=self.prim,
                  title=self.title,
                  price=self.price,
                  alreadyhave=self.alreadyhave,
                  coords=[self.latc,self.longc],
                  files=self.files.split(';')[:-1],
                  addres=self.addres,
                  tags=self.tags.split('#')[1:],
                  article=self.article,
                  desc=self.desc,
                  visibility=self.visibility)
    def to_dict2(self):
      return dict(id=self.id,
                  fromuser=self.fromuser,
                  prim=self.prim,
                  title=self.title,
                  price=self.price,
                  alreadyhave=self.alreadyhave,
                  files=self.files.split(';')[:-1],
                  desc=self.desc,
                  visibility=self.visibility)

class Tags(db.Model):
    __tablename__='tag'
    id=db.Column(db.Integer,primary_key=True)
    tag=db.Column(db.String(150),nullable=False)
    def to_dict(self):
      return dict(id=self.id,
                  tag=self.tag)