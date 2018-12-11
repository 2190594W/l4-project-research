import pyopenabe
# TODO: Consider dropping templates, for heightened security (sessions too)
from flask import Flask, flash, session, request, redirect,\
send_file, render_template, jsonify
from io import BytesIO
from sys import exc_info
from os import urandom, path
from datetime import datetime
from functools import partial


VERSION = 'v0.0.1'

MASTER_SECRET_KEY_FILE = 'master_secret_key.key'
MASTER_PUBLIC_KEY_FILE = 'master_public_key.key'

app = Flask(__name__)

try:
    with open('session_secret.config', 'rb') as session_secret:
        app.secret_key = session_secret.read().strip()
        if len(app.secret_key) > 32:
            app.logger.info("Configured session secret")
        else:
            raise ValueError("Insufficient session secret provided")
except:
    app.logger.error("No sufficient session secret found, auto-generated random 64-bytes.")
    app.secret_key = urandom(64)

openabe = pyopenabe.PyOpenABE()
cpabe_instance = openabe.CreateABEContext("CP-ABE")

try:
    with open(MASTER_SECRET_KEY_FILE, 'rb') as mskf:
        MASTER_SECRET_KEY = mskf.read()
    with open(MASTER_PUBLIC_KEY_FILE, 'rb') as mpkf:
        MASTER_PUBLIC_KEY = mpkf.read()
    cpabe_instance.importSecretParams(MASTER_SECRET_KEY)
    cpabe_instance.importPublicParams(MASTER_PUBLIC_KEY)
    MASTER_KEYS_GENERATED = datetime.fromtimestamp(path.getmtime(MASTER_SECRET_KEY_FILE))
except:
    try:
        cpabe_instance.generateParams()
        MASTER_SECRET_KEY = cpabe_instance.exportSecretParams()
        MASTER_PUBLIC_KEY = cpabe_instance.exportPublicParams()
        with open(MASTER_SECRET_KEY_FILE, 'wb') as mskf:
            mskf.write(MASTER_SECRET_KEY)
        with open(MASTER_PUBLIC_KEY_FILE, 'wb') as mpkf:
            mpkf.write(MASTER_PUBLIC_KEY)
        MASTER_KEYS_GENERATED = datetime.now()
    except:
        app.logger.error("FATAL ERROR: ABORTING SERVER")
        app.logger.error("Unexpected error:", exc_info()[0])
        exit()

del cpabe_instance, openabe

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/abe/get_public_key')
def get_public_key():
    mpk_payload = {
        'generated_at': MASTER_KEYS_GENERATED,
        'updated_at': datetime.now(),
        'mpk': MASTER_PUBLIC_KEY.decode('UTF-8'),
        'abe_version': VERSION
    }
    return jsonify(mpk_payload)

def assign_value_key(type, key, value):
    policy_separators = {"strings": ":", "integers": "=", "dates": " = ", "arrays": ":"}
    separator = policy_separators[type]
    value = ",".join(map(str, value)) if type == "arrays" else value
    return f"{key}{separator}{value}"

def create_policy(attrs):
    user_policy = "|"
    for attr_type, attrs in attrs.items():
        if attr_type in ('strings','integers','dates','arrays'):
            formatted_attrs = list(map(partial(assign_value_key, attr_type), attrs.keys(), attrs.values()))
            user_policy += "|".join(formatted_attrs) + "|"
        elif attr_type == "flags":
            user_policy += "|".join(attrs) + "|"
        else:
            pass
    return user_policy

@app.route('/abe/generate_userkey/json', methods=['POST'])
def generate_userkey_json():
    openabe = pyopenabe.PyOpenABE()
    cpabe_instance = openabe.CreateABEContext("CP-ABE")
    cpabe_instance.importSecretParams(MASTER_SECRET_KEY)
    cpabe_instance.importPublicParams(MASTER_PUBLIC_KEY)
    print("imported")
    user_attrs = request.get_json()
    if user_attrs is not None:
        if all(key in user_attrs for key in ('attributes', 'username')):
            str_username = str(user_attrs['username'])
            user_policy = create_policy(user_attrs['attributes'])
            print(user_policy)
            del user_attrs
            try:
                cpabe_instance.keygen(user_policy, str_username)
                print("successfully generated key")
                userkey_generated_at = datetime.now()
                userkey = cpabe_instance.exportUserKey(str_username)
            except:
                app.logger.error("Fatal error during key generation")
                return jsonify({'msg': 'FATAL ERROR'}), 500

            userkey_payload = {
                'filename': f"{str_username}.key",
                'generated_at': userkey_generated_at,
                'updated_at': datetime.now(),
                'userkey': userkey.decode('UTF-8'),
                'abe_version': VERSION
            }
            return jsonify(userkey_payload)
    return jsonify({'msg': 'Improper JSON values. Ensure both "attributes" and "username" keys are present!'}), 422

@app.route('/abe/generate_userkey/file', methods=['POST'])
def generate_userkey_file():
    openabe = pyopenabe.PyOpenABE()
    cpabe_instance = openabe.CreateABEContext("CP-ABE")
    cpabe_instance.importSecretParams(MASTER_SECRET_KEY)
    cpabe_instance.importPublicParams(MASTER_PUBLIC_KEY)
    print("imported")
    user_attrs = request.get_json()
    if user_attrs is not None:
        if all(key in user_attrs for key in ('attributes', 'username')):
            str_username = str(user_attrs['username'])
            user_policy = create_policy(user_attrs['attributes'])
            print(user_policy)
            del user_attrs
            try:
                cpabe_instance.keygen(user_policy, str_username)
                print("successfully generated key")
                userkey_generated_at = datetime.now()
                userkey = cpabe_instance.exportUserKey(str_username)
            except:
                app.logger.error("Fatal error during key generation")
                return jsonify({'msg': 'FATAL ERROR'}), 500

            userkey_payload = {
                'filename': f"{str_username}.key",
                'generated_at': userkey_generated_at,
                'updated_at': datetime.now(),
                'userkey': userkey.decode('UTF-8'),
                'abe_version': VERSION
            }
            return send_file(
                BytesIO(userkey),
                mimetype='text/plain',
                as_attachment=True,
                attachment_filename=f"{str_username}.key")
    return jsonify({'msg': 'Improper JSON values. Ensure both "attributes" and "username" keys are present!'}), 422

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
