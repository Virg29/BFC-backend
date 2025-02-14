from functools import wraps
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from flask import Blueprint, jsonify, request, current_app, redirect, url_for, send_from_directory
from flask_cors import CORS, cross_origin
import hashlib
import jwt
import copy

from .models import db, User, Post ,Tags

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in current_app.config['ALLOWED_EXTENSIONS']


api = Blueprint('api', __name__)

@api.route('/uploads/<path:filename>')
def download_file(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'],filename,as_attachment=True)

def token_required(f):
    @wraps(f)
    def _verify(*args, **kwargs):
        auth_headers = request.headers.get('Authorization', '')
        print(auth_headers)
        invalid_msg = {
            'message': 'Неправильный токен',
            'status': False
        }
        expired_msg = {
            'message': 'Недействительный токен',
            'status': False
        }
        if(len(auth_headers)<10):
            return invalid_msg
        try:
            token = auth_headers
            data = jwt.decode(token, current_app.config['SECRET_KEY'],algorithms=['HS256'])
            print(data)
            user = User.query.filter_by(login=data['sub']).filter_by(logged=True).first()
            print(user.login)
            if not user:
                return jsonify({ 'message': 'Invalid credentials', 'status': False }), 200
            return f(user, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify(expired_msg), 200 # 401 is Unauthorized HTTP status code
        except (jwt.InvalidTokenError, Exception) as e:
            print(e)
            return jsonify(invalid_msg), 401

    return _verify

@api.route('/tags')
def say_hello():
    resp=[]
    for i in Tags.query.all():
        resp.append(i.to_dict())
    return(jsonify(resp))



@api.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    print(data)
    if(data=="{}"):
        return jsonify({'status':False,'message':'Неправильные параметры POST запроса'}), 200
    if data==None:
        return jsonify({'status':False,'message':'Неправильные параметры POST запроса'}), 200
    users = User.query.filter_by(login=data['login']).all()
    if(len(users)!=0):
        return jsonify({'status':False,'message':'Логин занят'}), 200
    user = User(**data)
    db.session.add(user)
    db.session.commit()
    token = jwt.encode({
        'sub': user.login,
        'iat':datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=30)},
        current_app.config['SECRET_KEY'])
    return jsonify({ 'token': token.decode('UTF-8'),'status':True })

@api.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if data==None:
        return jsonify({'status':False,'msg':'Неправильные параметры POST запроса'}), 200
    user = User.authenticate(**data)

    if not user:
        return jsonify({ 'message': 'Логин и/или пароль неверные', 'status': False }), 200
    user.logged=True
    db.session.commit()
    token = jwt.encode({
        'sub': user.login,
        'iat':datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=30)},
        current_app.config['SECRET_KEY'])
    return jsonify({ 'token': token.decode('UTF-8'),'status':True })

@api.route('/auth/test', methods=['POST'])
@token_required
def test(user):
    return(user.login)

@api.route('/auth/logout', methods=['POST'])
@token_required
def logout(user):
    user.logged=False
    db.session.commit()
    return jsonify({'status':True,'message':'logouted'})

@api.route('/new/generate_new', methods=['POST'])
@token_required
def generate_new(user):
    data = {'fromuser':user.login}
    post = Post(**data)
    db.session.add(post)
    db.session.commit()
    return jsonify({'status':True,'id':post.id}), 200

@api.route('/new/loadImages', methods=['POST'])
@token_required
def loadImages(user):
    postid = request.headers.get('room-Allow', '')
    file = request.files['file']
    if file and allowed_file(file.filename):
        ext=file.filename.rsplit('.',1)[1]
        hashedTime=hashlib.md5(str(datetime.utcnow()).encode('UTF-8')).hexdigest()+'.'+ext
        request.files['file'].save(current_app.config['UPLOAD_FOLDER']+'/'+hashedTime)
        chosenpost=Post.query.filter_by(id=postid).first()
        chosenpost.files+=hashedTime+";"
        db.session.commit()
        return("")



@api.route('/new/removeRoom', methods=['DELETE'])
@token_required
def removeRoom(user):
    data = request.get_json()
    postid = data['id']
    Post.query.filter(Post.id==postid).filter(Post.fromuser==user.login).delete()
    db.session.commit()

@api.route('/new/loadJson', methods=['POST'])
@token_required
def loadJson(user):
    data = request.get_json()
    print(data)
    postid = data['id']
    q=Post.query.filter_by(id=postid).filter_by(fromuser=user.login).first()
    if not q:
        return(jsonify({'status':False}))
    q.title=data['title']
    q.price=data['total']
    q.latc=data['coord'][0]
    q.longc=data['coord'][1]
    q.visibility=True
    q.prim=hashlib.md5(str(datetime.utcnow()).encode('UTF-8')).hexdigest()
    tagstemp=""
    for i in data['tags']:
        newtag=Tags(tag=i)
        db.session.add(newtag)
        tagstemp+="#"+i
    q.tags=tagstemp
    q.article=data['article']
    q.desc=data['desc']
    db.session.commit()
    return ""

@api.route('/getposts',methods=['POST'])
def viewposts():
    data = request.get_json()
    
    #offset = data['offset']
    offset = 3
    resp=[]
    q = Post.query.all()
    for k in data:
        if(k=="tags"):
            tags = data['tags']
            for i in tags:
                print(i)
                for j in q:
                    if(i in j.tags.split('#')[1:]):
                        resp.append(j.to_dict2())
                        q.remove(j)
        if(k=='coord'):
            coord = data['coord']
            for j in q:
                if(abs(float(j.latc)-float(coord[0]))<0.1 and abs(float(j.longc)-float(coord[1]))<0.1):
                    resp.append(j.to_dict2())
                    q.remove(j)
        if(k=='page'):
            page = data['page']
            for j in Post.query.order_by(Post.id.desc()).offset(offset*page).limit(offset).all():
                resp.append(j.to_dict2())
    return(jsonify(resp))
@api.route('/post',methods=['GET'])
def getpost():
    postid = request.args.get('id')
    return jsonify(Post.query.filter_by(id=postid).first().to_dict())


@api.after_request
def creds(response):
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, authorization, cache-control, room-Allow, x-requested-with'
    response.headers['Access-Control-Expose-Headers'] = 'Cookie'
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response


