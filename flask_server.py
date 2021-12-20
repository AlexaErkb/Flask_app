import binascii
import json
import os
from flask import Flask, jsonify, abort,  request
import hashlib
import datetime
from hashlib import sha256
users = []
app = Flask(__name__)

try:
	with open('users.json', 'r') as js_file:
		users = json.load(js_file)
except FileNotFoundError:
	with open('users.json', 'w') as js_file:
		json.dump(users, js_file)

def js_load(users):
	with open('users.json', 'w') as js_file:
		json.dump(users, js_file)

def hasher(password, salt=None):
	if salt == None:
		salt = sha256(os.urandom(70)).hexdigest().encode('ascii')
		key = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 80000)
		key = binascii.hexlify(key)
		return (salt + key).decode('ascii'), salt.decode('ascii')
	else:
		salt = salt.encode('ascii')
		new_key = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 80000)
		new_key = binascii.hexlify(new_key)
		return (salt + new_key).decode('ascii')

def create(inf):
	try:
		tu = hasher(inf['password'])
		new_user = {
			'login':inf['login'],
			'password':tu[0],
			'salt':tu[1],
			'regDate': datetime.datetime.now().isoformat()
		}
		users.append(new_user)
		js_load(users)
		return {
			'result': 'Пользователь зарегистрирован'
		}, 201
	except:
		abort(400)

def check_login(login):
	for i in range(len(users)):
		if users[i]['login'] == login:
			return False
	return True
@app.route('/user/registration', methods=['POST'])
def create_users():
	ifuser = request.get_json()
	if check_login(ifuser['login']):
		return create(ifuser)
	else:
		return {
			'result':'Такой логин уже существует'
		}
def check_pass(inf):
	login = inf['login']
	password = inf['password']
	list_ch = list(filter(lambda x: x['login'] == login, users))
	pass_check = list_ch[0]['password']
	salt_check = list_ch[0]['salt']
	new_pass = hasher(password, salt_check)
	if pass_check == new_pass:
		return True
	else:
		return False

@app.route('/user', methods=['POST'])
def log_and_get_users():
	ifuser = request.get_json()
	if not check_login(ifuser['login']):
		if check_pass(ifuser):
			return {
				'result': 'Вы успешно авторизированы'
			}
		else:
			return {
				'result': 'Другой пароль'
			}

	else:
		return {
			'result': 'Такого пользователя не существует'
		}


@app.route('/user/get', methods=['GET'])
def get_users():
	return jsonify({"users": users})

@app.route('/')
def user_data():
    abort(404)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)
