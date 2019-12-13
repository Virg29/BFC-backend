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
        return jsonify({'status':False}), 201
    user = User(**data)
    db.session.add(user)
    db.session.commit()
    return jsonify({'status':True}), 201