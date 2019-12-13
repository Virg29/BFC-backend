from functools import wraps
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, current_app

import jwt

from .models import db, User

api = Blueprint('api', __name__)

@api.route('/hello/<string:name>/')
def say_hello(name):
    response = { 'msg': "Hello {}".format(name) }
    return jsonify(response)

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
        return jsonify({ 'message': 'Invalid credentials', 'authenticated': False }), 401

    token = jwt.encode({
        'sub': user.login,
        'iat':datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=30)},
        current_app.config['SECRET_KEY'])
    return jsonify({ 'token': token.decode('UTF-8') })