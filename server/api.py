#!/usr/bin/env python
from collections import defaultdict
import os
import json
from ConfigParser import SafeConfigParser
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import literal
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

# initialization
parser = SafeConfigParser()
parser.read('config.ini')
app = Flask(__name__)
app.config['SECRET_KEY'] = parser.get('server_config', 'SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = parser.get('server_config', 'DB_URI')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user

class Data(db.Model):
    __tablename__ = 'data'
    record_id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(32))
    uname = db.Column(db.String(32))
    key = db.Column(db.String(4096))
    passw = db.Column(db.String(128))
    comments = db.Column(db.String(500))
    uid = db.Column(db.String(32), db.ForeignKey('users.username'))

    @staticmethod
    def search_user_record(uid): 
        rows = Data.query.filter_by(record_id==uid)
        return rows

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})

@app.route('/api/records/new', methods=['POST'])
@auth.login_required
def new_record():
    # gets the values the user sends over in their request
    ip = request.json.get('ip')
    uname = request.json.get('uname')
    key = request.json.get('key')
    passw = request.json.get('passw')
    comments = request.json.get('comments')
    uid = g.user.id # gets the users id for the foreign key value in db
    if ip is None or uname is None or key is None or passw is None:
        abort(400)
    else:
        data = Data(ip=ip, uname=uname, key=key, passw=passw, comments=comments, uid=uid)
        db.session.add(data)
        db.session.commit()
    return jsonify({'ip':ip,'uname':uname,'key':key,'passw':passw,"uid":g.user.id})

@app.route('/api/records/get')
@auth.login_required
def get_records():
    uuid = g.user.id #gets users ID so we can find all records for our user and return them.
    rows = Data.query.filter_by(uid=uuid).all()
    rtrn_row = defaultdict(dict)
    l_one = {}
    i = 0
    for r in rows:
        print "++++++++++++++++++++"
        rtrn_row[i][0] = r.record_id
        print "____",r.record_id,"____"
        rtrn_row[i][1] = r.ip
        print "____",r.ip,"____"
        rtrn_row[i][2] = r.key
        print "____",r.key,"____"
        rtrn_row[i][3] = r.uname
        print "____",r.uname,"____"
        rtrn_row[i][4] = r.passw
        print "____",r.passw,"____"
        rtrn_row[i][5] = r.comments
        print "____",r.comments,"____"
        i = i + 1
    return jsonify(rtrn_row)

@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
