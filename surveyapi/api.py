from functools import wraps
from datetime import datetime, timedelta
import os

from flask import Blueprint, jsonify, request, current_app

import jwt

from .models import db, User

api = Blueprint('api', __name__)

def token_required(f):
    @wraps(f)
    def _verify(*args, **kwargs):
        auth_headers = request.headers.get('Authorization', '')
        print(auth_headers)
        invalid_msg = {
            'message': 'Invalid token. Registeration and / or authentication required',
            'authenticated': False
        }
        expired_msg = {
            'message': 'Expired token. Reauthentication required.',
            'authenticated': False
        }

        try:
            token = auth_headers
            data = jwt.decode(token, current_app.config['SECRET_KEY'],algorithms=['HS256'])
            user = User.query.filter_by(login=data['sub']).first()
            if not user:
                return jsonify({ 'message': 'Invalid credentials', 'status': False }), 401
            return f(user, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify(expired_msg), 401 # 401 is Unauthorized HTTP status code
        except (jwt.InvalidTokenError, Exception) as e:
            print(e)
            return jsonify(invalid_msg), 401

    return _verify

@api.route('/hello')
def say_hello():
    return('1')

@api.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if data==None:
        return jsonify({'status':False,'msg':'Неправильные параметры POST запроса'}), 201
    users = User.query.filter_by(login=data['login']).all()
    if(len(users)!=0):
        return jsonify({'status':False,'msg':'Логин занят'}), 201
    user = User(**data)
    db.session.add(user)
    db.session.commit()
    return jsonify({'status':True}), 201

@api.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if data==None:
        return jsonify({'status':False,'msg':'Неправильные параметры POST запроса'}), 201

    user = User.authenticate(**data)

    if not user:
        return jsonify({ 'message': 'Логин и/или пароль неверные', 'status': False }), 401

    token = jwt.encode({
        'sub': user.login,
        'iat':datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=30)},
        current_app.config['SECRET_KEY'],algorithms=['HS256'])
    return jsonify({ 'token': token.decode('UTF-8') })

@api.route('/auth/test', methods=['POST'])
@token_required
def test(user):
    return(user.login)

@api.route('/newpost', methods=['POST'])
@token_required
def newpost(user):
    pass




