import os
import pyotp
import json
import firebase_admin
import random
import hashlib
import time
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from datetime import datetime
from flask import *
from flask_login import *
from flask_qrcode import *
from turbo_flask import *
from threading import Thread
from firebase_admin import credentials
from firebase_admin import db

cred_file = 'honeypot.json'
cred = credentials.Certificate(cred_file)
firebase_admin.initialize_app(cred, {'databaseURL' : 'https://honeypot-349512-default-rtdb.firebaseio.com/'})
ref = db.reference('/')
app = Flask(__name__)
app.config['SECRET_KEY'] = hashlib.md5(str(random.randint(1, 10000)).encode()).hexdigest()
login = LoginManager(app)
turbo = Turbo(app)
qrcode = QRcode(app)
user = UserMixin()

login.login_view = 'login'
user.id = ''

def update_top_info():
    with app.app_context():
        while True:
            turbo.push(
                turbo.update(render_template("top_log.html", log=random.randint(1, 100)), "top_log"))
            time.sleep(5)

@login.user_loader
def user_loader(username):
    user_ref = ref.child("user_info")
    user_info = user_ref.get()
    if user_info is not None:
        if username not in user_info.keys():
            return

        user.id = username
        return user
    else: 
        return

@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    user.id = ''
    return redirect('/')

@app.route("/get_sysinfo", methods=['GET'])
@login_required
def get_sysinfo():
    info_ref = ref.child('info')
    info_data = info_ref.get()

@app.route("/api", methods=['GET', 'POST'])
@login_required
def api():
    user_ref = ref.child("user_info").child(str(user.get_id()))
    user_info = user_ref.get()

    has_token = user_info['has_token']
    
    if request.method == 'POST':
        password = request.form['password']
        otp_code = request.form['otpcode']
        current_hash_password = hashlib.sha256(password.encode()).hexdigest()
        hash_password = user_info['password']
        encrypt_otp_key = user_info['otp_key']
        if current_hash_password == hash_password:
            key = JWK.from_password(pad(password.encode(), 32).decode())
            jwt = JWT()
            jwt.deserialize(encrypt_otp_key, key)
            otp_key = json.loads(jwt.claims)['otp_key']
            totp = pyotp.TOTP(otp_key)
            if totp.verify(otp_code):
                if not has_token:
                    key = RSA.generate(2048)
                    private_key = key.export_key(format='PEM')
                    public_key = key.public_key().export_key(format='PEM')
                    load_key = RSA.import_key(public_key)
                    rsa = PKCS1_OAEP.new(load_key, hashAlgo=SHA256.new())
                    encrypt_data = base64.b64encode(rsa.encrypt(user.get_id().encode())).decode()
                    private_key = base64.b64encode(private_key).decode()

                    key = JWK.from_password(pad(password.encode(), 32).decode())
                    info = {"iat": int(datetime.timestamp(datetime.now())),
                        "data": encrypt_data,
                        "private_key": private_key}
                    jwt = JWT(header={
                        "alg": "A256KW", "enc": "A256CBC-HS512"}, claims=info)
                    jwt.make_encrypted_token(key)
                    token = jwt.serialize()
                    user_ref.update({
                        "has_token": True,
                        "token": token})  
                    return Response(render_template('api.html', has_token=True, token=token, message="REST API has enable."), 302)      
                else:
                    token_ref = user_ref.child("token")
                    user_ref.update({
                        "has_token": False})
                    token_ref.delete()
                    return Response(render_template('api.html', has_token=False, message="REST API has disable."), 302)
            else:
                if has_token:
                    token = user_info['token']
                    return Response(render_template('api.html', has_token=has_token, token=token, message="OTP verify error."), 302)
                else:
                    return Response(render_template('api.html', has_token=has_token, message="OTP verify error."), 302)
        else:
            if has_token:
                token = user_info['token']
                return Response(render_template('api.html', has_token=has_token, token=token, message="Password verify error."), 302)
            else:
                return Response(render_template('api.html', has_token=has_token, message="Password verify error."), 302)

    if has_token:
        token = user_info['token']
        return render_template('api.html', has_token=has_token, token=token)
    else:
        return render_template('api.html', has_token=has_token)

@app.route("/blacklist", methods=['GET', 'POST'])
@login_required
def blacklist():
    blacklist_ref = ref.child("blacklist")

@app.route("/add_blacklist/<ip>", methods=['POST'])
def add_blacklist(ip):
    user_ref = ref.child("user_info")
    blacklist_ref = ref.child("blacklist")
    user_info = user_ref.get()
    ip = str(ip).replace('.', '-')
    
    if 'token' not in request.form.keys() or 'password' not in request.form.keys():
        return {"status": "Please input field."}

    token = str(request.form['token'])
    password = str(request.form['password'])

    try:
        key = JWK.from_password(pad(password.encode(), 32).decode())
        jwt = JWT()
        jwt.deserialize(token, key)
        encrypt_data = base64.b64decode(json.loads(jwt.claims)['data'])
        private_key = base64.b64decode(json.loads(jwt.claims)['private_key'])
        load_key = RSA.import_key(private_key)
        rsa = PKCS1_OAEP.new(load_key, hashAlgo=SHA256.new())
        username = rsa.decrypt(encrypt_data).decode()
        
        if user_info is None:
            return {"status": "Data is Empty."}

        if not user_info[username]['has_token']:
            return {"status": "REST API not enable."}

        if username in user_info.keys():
            if token == user_info[username]['token']:
                if blacklist_ref.get() is None:
                    blacklist_ref.child(ip).update({"add_account": username})
                    return {"status": "Success or ip is not exist.", "add_account": username}
                if ip not in blacklist_ref.get().keys():
                    blacklist_ref.child(ip).update({"add_account": username})
                    return {"status": "Success.", "add_account": username}
                else:
                    return {"status": "This IP has add blacklist."}
            else:
                return {"status": "Token expired."}
        else:
            return {"status": "Username is not exist."}
    except:
        return {"status": "API Key verify Error."}

@app.route("/delete_blacklist/<ip>", methods=['POST'])
def delete_blacklist(ip):
    user_ref = ref.child("user_info")
    blacklist_ref = ref.child("blacklist")
    user_info = user_ref.get()
    ip = str(ip).replace('.', '-')

    if 'token' not in request.form.keys() or 'password' not in request.form.keys():
        return {"status": "Please input field."}

    token = str(request.form['token'])
    password = str(request.form['password'])

    try:
        key = JWK.from_password(pad(password.encode(), 32).decode())
        jwt = JWT()
        jwt.deserialize(token, key)
        encrypt_data = base64.b64decode(json.loads(jwt.claims)['data'])
        private_key = base64.b64decode(json.loads(jwt.claims)['private_key'])
        load_key = RSA.import_key(private_key)
        rsa = PKCS1_OAEP.new(load_key, hashAlgo=SHA256.new())
        username = rsa.decrypt(encrypt_data).decode()

        if user_info is None:
            return {"status": "Data is Empty."}

        if not user_info[username]['has_token']:
            return {"status": "REST API not enable."}
    
        if username in user_info.keys():
            if token == user_info[username]['token']:
                if blacklist_ref.get() is None:
                    blacklist_ref.child(ip).delete()
                    return {"status": "Success.", "delete_account": username}
                if ip in blacklist_ref.get().keys():
                    blacklist_ref.child(ip).delete()
                    return {"status": "Success.", "delete_account": username}
                else:
                    return {"status": "This IP has delete blacklist or not exist."}
            else:
                return {"status": "Token expired."}
        else:
            return {"status": "Username is not exist."}
    except:
        return {"status": "API Key verify Error."}

@app.route("/get_blacklist", methods=['POST'])
def get_blacklist():
    user_ref = ref.child("user_info")
    blacklist_ref = ref.child("blacklist")
    blacklist_info = blacklist_ref.get()
    user_info = user_ref.get()
    ip = str(ip).replace('.', '-')

    if 'token' not in request.form.keys() or 'password' not in request.form.keys():
        return {"status": "Please input field."}

    token = str(request.form['token'])
    password = str(request.form['password'])

    try:  
        key = JWK.from_password(pad(password.encode(), 32).decode())
        jwt = JWT()
        jwt.deserialize(token, key)
        encrypt_data = base64.b64decode(json.loads(jwt.claims)['data'])
        private_key = base64.b64decode(json.loads(jwt.claims)['private_key'])
        load_key = RSA.import_key(private_key)
        rsa = PKCS1_OAEP.new(load_key, hashAlgo=SHA256.new())
        username = rsa.decrypt(encrypt_data).decode()

        if user_info is None:
            return {"status": "Data is Empty."}
        
        if not user_info[username]['has_token']:
            return {"status": "REST API not enable."}

        if username in user_info.keys():
            if token == user_info[username]['token']:
                if blacklist_info is not None:
                    return {"status": "Success.", "data": blacklist_info}
                else:
                    return {"status": "The blacklist is empty."}
            else:
                return {"status": "Token expired."}
        else:
            return {"status": "Username is not exist."}
    except:
        return {"status": "API Key verify Error."}

@app.route("/register", methods=['GET', 'POST'])
def register():

    if user.get_id() != '':
        logout_user()
        user.id = ''
        return redirect('/')

    random_key = pyotp.random_base32()
    totp = pyotp.TOTP(random_key)
    qr_url = totp.provisioning_uri(issuer_name='HoneypotWeb')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otpcode = request.form['otpcode']
        otp_key = request.form['otpkey']

        totp = pyotp.TOTP(otp_key)
        qr_url = totp.provisioning_uri(issuer_name='HoneypotWeb')
        hash_password = hashlib.sha256(password.encode()).hexdigest()
        user_ref = ref.child("user_info").child(str(username))
        info = {"otp_key": otp_key}

        key = JWK.from_password(pad(password.encode(), 32).decode())
        jwt = JWT(header={"alg": "A256KW", "enc": "A256CBC-HS512"}, claims=info)
        jwt.make_encrypted_token(key)
        encrypt_otp_key = jwt.serialize()

        if totp.verify(otpcode):
            user_ref.update({
                "password": hash_password,
                "otp_key": encrypt_otp_key,
                "has_token" : False})
            return redirect('/')
        else:
            return Response(render_template('register.html', error='OTP verify error.', keys=otp_key, qr_url=qr_url), 302)
        
    return render_template('register.html', keys=random_key, qr_url=qr_url)

@app.route("/manager", methods=['GET'])
@login_required
def manager():
    thread = Thread(target=update_top_info)
    thread.start()
    return render_template("manager.html")

@app.route("/delete_account", methods=['GET', 'POST'])
@login_required
def detete_account():
    if request.method == 'POST':
        user_ref = ref.child("user_info").child(str(user.get_id()))
        user_info = user_ref.get()

        password = request.form['password']
        current_hash_password = hashlib.sha256(password.encode()).hexdigest()
        otpcode = request.form['otpcode']
        
        hash_password = user_info['password']
        encrypt_otp_key = user_info['otp_key']
       
        if current_hash_password == hash_password:
            key = JWK.from_password(pad(password.encode(), 32).decode())
            jwt = JWT()
            jwt.deserialize(encrypt_otp_key, key)
            otp_key = json.loads(jwt.claims)['otp_key']
            totp = pyotp.TOTP(otp_key)
            verify = totp.verify(otpcode)
            if verify:
                user_ref.delete()
                logout_user()
                user.id = ''
                return redirect('/')
            else:
                return Response(render_template('delete_account.html', error='OTP verify error.'), 302)
        else:
            return Response(render_template('delete_account.html', error='Password verify error.'), 302)
    return render_template('delete_account.html')

@app.route("/", methods=['GET', 'POST'])
def main():

    if user.get_id() != '': 
        logout_user()
        user.id = ''
        return redirect('/')

    if request.method == 'POST':
        user_ref = ref.child("user_info")
        user_info = user_ref.get()

        username = request.form['username']
        password = request.form['password']
        current_hash_password = hashlib.sha256(password.encode()).hexdigest()
        otpcode = request.form['otpcode']
        
        if user_info is None:
            return render_template('index.html', error='Login Fail... Database is not data.')
        if username in user_info.keys():

            hash_password = user_info[username]['password']
            encrypt_otp_key = user_info[username]['otp_key']
          
            if current_hash_password == hash_password:
                key = JWK.from_password(pad(password.encode(), 32).decode())
                jwt = JWT()
                jwt.deserialize(encrypt_otp_key, key)
                otp_key = json.loads(jwt.claims)['otp_key']
                totp = pyotp.TOTP(otp_key)
                verify = totp.verify(otpcode)
                if verify:
                    user.id = username
                    login_user(user)
                    return redirect('/manager')
                else:
                    return Response(render_template('index.html', error='Login Fail... OTP verify error.'), 302)
            else:
                return  Response(render_template('index.html', error='Login Fail... Password verify error.'), 302)
        else:
            return Response(render_template('index.html', error='Login Fail... Username is not exist.'), 302)
    return render_template('index.html')

@login.unauthorized_handler
def unauth():
    return render_template('unauth.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)