import os
import pyotp
import json
import firebase_admin
import random
import hashlib
import time
from collections import Counter, defaultdict
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK
from Crypto.Util.Padding import pad
from flask import *
from flask_login import *
from flask_qrcode import *
from turbo_flask import *
from threading import Timer
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

def event_top_classes(event_json):
    count = Counter(defaultdict(lambda : 0))
    if event_json is None:
        return count
    for timestamp in event_json.keys():
        if "ShellCode" in event_json[timestamp]['event_type']:
            count["ShellCode"] += 1
        elif "PORT Scan" in event_json[timestamp]['event_type']:
            if "XMAS" in event_json[timestamp]['scan_type']:
                count["PORT Scan XMAS"] += 1
            if "NULL" in event_json[timestamp]['scan_type']:
                count["PORT Scan NULL"] += 1
            if "FIN" in event_json[timestamp]['scan_type']:
                count["PORT Scan FIN"] += 1
        elif "Syn Flood" in event_json[timestamp]['event_type']:
            count["Syn Flood"] += 1
        elif "DNS Fuzz" in event_json[timestamp]['event_type']:
            count["DNS Fuzz"] += 1
    top_most = count.most_common(3)
    return top_most

def protocol_classes(connect_json):
    tcp_count, udp_count = 0, 0
    for timestamp in connect_json.keys():
        if "TCP" in connect_json[timestamp]['l3_protocol']:
            tcp_count += 1
        elif "UDP" in connect_json[timestamp]['l3_protocol']:
            udp_count += 1
    return tcp_count, udp_count

def update_sysinfo():
    with app.app_context():
        while True:
            info_ref = ref.child("info")
            info_json = info_ref.get()
            turbo.push(
                turbo.update(render_template(
                    "update_sysinfo.html", data=info_json), "sysinfo"))
            time.sleep(1)

def update_live_event():
    with app.app_context():
        while True:
            event_ref = ref.child("event")
            event_json = event_ref.get()
            if event_json is None:
                event_n = 0
                event_json = dict()
            else:
                event_n = len(event_json)
            top_classes = event_top_classes(event_json)
            top_n = len(top_classes)
            turbo.push(
                turbo.update(render_template(
                    "update_event.html",
                    event_n=event_n, 
                    event_json=event_json,
                    top_n = range(1, top_n + 1),
                    top_classes=top_classes), "live_event"))
            time.sleep(1)

def update_live_connect():
    with app.app_context():
        while True:
            connect_ref = ref.child("connect_info")
            connect_json = connect_ref.get()
            if connect_json is None:
                connect_n = 0
                connect_json = dict()
            else:
                connect_n = len(connect_json)
            tcp_n, udp_n = protocol_classes(connect_json)
            turbo.push(
                turbo.update(render_template(
                    "update_connect.html",
                    connect_n=connect_n, 
                    connect_json=connect_json,
                    tcp_n=tcp_n,
                    udp_n=udp_n), "live_connect"))
            time.sleep(1)

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

@app.route("/sysinfo", methods=['GET'])
@login_required
def sysinfo():
    timer = Timer(interval=1, function=update_sysinfo)
    timer.start()
    return render_template("sysinfo.html")

@app.route("/connectinfo", methods=['GET'])
@login_required
def connectinfo():
    timer = Timer(interval=1, function=update_live_connect)
    timer.start()
    return render_template("connect.html")

@app.route("/event", methods=['GET'])
@login_required
def event():
    timer = Timer(interval=1, function=update_live_event)
    timer.start()
    return render_template("event.html")

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
                    key = JWK.from_password(pad(password.encode(), 32).decode())
                    info = {"iat": int(time.time()),
                        "data": user.get_id()}

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

@app.route("/delete_event/<ip_address>", methods=["GET"])
@login_required
def delete_event(ip_address):
    blacklist_ref = ref.child("blacklist")
    blacklist_json = blacklist_ref.get()
    if ip_address in blacklist_json.keys():
        blacklist_ref.child(ip_address).delete()
        return redirect("/blacklist")

@app.route("/blacklist", methods=['GET', 'POST'])
@login_required
def blacklist():
    blacklist_ref = ref.child("blacklist")
    blacklist_json = blacklist_ref.get()
    
    if blacklist_json is None:
        blacklist_json = dict()

    if request.method == "POST":
        ip = request.form["ip_address"]
        if ip.replace(".", "-") not in blacklist_json.keys():
            blacklist_ref.child(ip.replace(".", "-")).update({"add_account": user.get_id()})
            blacklist_json = blacklist_ref.get()
            return Response(render_template("blacklist.html", blacklist_json=blacklist_json, username=user.get_id(), message="Success."), 302)
        else:
            return Response(render_template("blacklist.html", blacklist_json=blacklist_json, username=user.get_id(), message="This IP has add blacklist."), 302)

    return render_template("blacklist.html", blacklist_json=blacklist_json, username=user.get_id())

@app.route("/add_blacklist/<ip>", methods=['POST'])
def add_blacklist(ip):
    user_ref = ref.child("user_info")
    blacklist_ref = ref.child("blacklist")
    user_info = user_ref.get()
    ip = str(ip).replace('.', '-')
    
    if 'token' not in request.values.keys() or 'password' not in request.values.keys():
        return {"status": "Please input field."}

    token = str(request.values['token'])
    password = str(request.values['password'])

    try:
        key = JWK.from_password(pad(password.encode(), 32).decode())
        jwt = JWT()
        jwt.deserialize(token, key)
        username = json.loads(jwt.claims)['data']
        
        if user_info is None:
            return {"status": "Data is Empty."}

        if not user_info[username]['has_token']:
            return {"status": "REST API not enable."}

        if username in user_info.keys():
            if token == user_info[username]['token']:
                if blacklist_ref.get() is None:
                    blacklist_ref.child(ip).update({"add_account": username})
                    return {"status": "Success.", "add_account": username}
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

    if 'token' not in request.values.keys() or 'password' not in request.values.keys():
        return {"status": "Please input field."}

    token = str(request.values['token'])
    password = str(request.values['password'])

    try:
        key = JWK.from_password(pad(password.encode(), 32).decode())
        jwt = JWT()
        jwt.deserialize(token, key)
        username = json.loads(jwt.claims)['data']

        if user_info is None:
            return {"status": "Data is Empty."}

        if not user_info[username]['has_token']:
            return {"status": "REST API not enable."}
    
        if username in user_info.keys():
            if token == user_info[username]['token']:
                if blacklist_ref.get() is None:
                    blacklist_ref.child(ip).delete()
                    return {"status": "Success or ip address is not exist.", "delete_account": username}
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

    if 'token' not in request.values.keys() or 'password' not in request.values.keys():
        return {"status": "Please input field."}

    token = str(request.values['token'])
    password = str(request.values['password'])

    try:  
        key = JWK.from_password(pad(password.encode(), 32).decode())
        jwt = JWT()
        jwt.deserialize(token, key)
        username = json.loads(jwt.claims)['data']

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

@app.route("/get_sysinfo", methods=['POST'])
def get_sysinfo():
    info_ref = ref.child("info")
    user_ref = ref.child("user_info")
    info_data = info_ref.get()
    user_info = user_ref.get()

    if 'token' not in request.values.keys() or 'password' not in request.values.keys():
        return {"status": "Please input field."}

    token = str(request.values['token'])
    password = str(request.values['password'])

    try:  
        key = JWK.from_password(pad(password.encode(), 32).decode())
        jwt = JWT()
        jwt.deserialize(token, key)
        username = json.loads(jwt.claims)['data']

        if user_info is None:
            return {"status": "Data is Empty."}
        
        if not user_info[username]['has_token']:
            return {"status": "REST API not enable."}

        if username in user_info.keys():
            if token == user_info[username]['token']:
                if info_data is not None:
                    return {"status": "Success.", "data": info_data}
                else:
                    return {"status": "The data is empty."}
            else:
                return {"status": "Token expired."}
        else:
            return {"status": "Username is not exist."}
    except:
        return {"status": "API Key verify Error."}

@app.route("/get_logger", methods=['POST'])
def get_logger():
    connect_ref = ref.child("connect_info")
    user_ref = ref.child("user_info")
    connect_data = connect_ref.get()
    user_info = user_ref.get()

    if 'token' not in request.values.keys() or 'password' not in request.values.keys():
        return {"status": "Please input field."}

    token = str(request.values['token'])
    password = str(request.values['password'])

    try:  
        key = JWK.from_password(pad(password.encode(), 32).decode())
        jwt = JWT()
        jwt.deserialize(token, key)
        username = json.loads(jwt.claims)['data']

        if user_info is None:
            return {"status": "Data is Empty."}
        
        if not user_info[username]['has_token']:
            return {"status": "REST API not enable."}

        if username in user_info.keys():
            if token == user_info[username]['token']:
                if connect_data is not None:
                    return {"status": "Success.", "data": connect_data}
                else:
                    return {"status": "The data is empty."}
            else:
                return {"status": "Token expired."}
        else:
            return {"status": "Username is not exist."}
    except:
        return {"status": "API Key verify Error."}

@app.route("/get_top3_event", methods=['POST'])
def get_top3_event():
    event_ref = ref.child("event")
    user_ref = ref.child("user_info")
    event_json = event_ref.get()
    event_top3 = event_top_classes(event_json)
    user_info = user_ref.get()

    if 'token' not in request.values.keys() or 'password' not in request.values.keys():
        return {"status": "Please input field."}

    token = str(request.values['token'])
    password = str(request.values['password'])

    try:  
        key = JWK.from_password(pad(password.encode(), 32).decode())
        jwt = JWT()
        jwt.deserialize(token, key)
        username = json.loads(jwt.claims)['data']

        if user_info is None:
            return {"status": "Data is Empty."}
        
        if not user_info[username]['has_token']:
            return {"status": "REST API not enable."}

        if username in user_info.keys():
            if token == user_info[username]['token']:
                if event_top3 is not None:
                    return {"status": "Success.", "data": event_top3}
                else:
                    return {"status": "The data is empty."}
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
    user_ref = ref.child("user_info")
    user_info = user_ref.get()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otpcode = request.form['otpcode']
        otp_key = request.form['otpkey']
      
        totp = pyotp.TOTP(otp_key)
        qr_url = totp.provisioning_uri(issuer_name='HoneypotWeb')
        hash_password = hashlib.sha256(password.encode()).hexdigest()

        if user_info is not None:
            if username in user_info.keys():
                return Response(render_template('register.html', error='This username is exist.', keys=otp_key, qr_url=qr_url), 302)

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
                return Response(render_template('index.html', error='Login Fail... Password verify error.'), 302)
        else:
            return Response(render_template('index.html', error='Login Fail... Username is not exist.'), 302)
    return render_template('index.html')

@login.unauthorized_handler
def unauth():
    return render_template('unauth.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))