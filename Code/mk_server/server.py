import os, sys, datetime, pyopenabe
# TODO: Consider dropping templates, for heightened security (sessions too)
from flask import Flask, flash, session, request, redirect, render_template, jsonify

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
    app.secret_key = os.urandom(64)

openabe = pyopenabe.PyOpenABE()
cpabe_instance = openabe.CreateABEContext("CP-ABE")

try:
    with open(MASTER_SECRET_KEY_FILE, 'rb') as mskf:
        MASTER_SECRET_KEY = mskf.read()
    with open(MASTER_PUBLIC_KEY_FILE, 'rb') as mpkf:
        MASTER_PUBLIC_KEY = mpkf.read()
    cpabe_instance.importSecretParams(MASTER_SECRET_KEY)
    cpabe_instance.importPublicParams(MASTER_PUBLIC_KEY)
    MASTER_KEYS_GENERATED = datetime.datetime.fromtimestamp(os.path.getmtime(MASTER_SECRET_KEY_FILE))
except:
    try:
        cpabe_instance.generateParams()
        MASTER_SECRET_KEY = cpabe_instance.exportSecretParams()
        MASTER_PUBLIC_KEY = cpabe_instance.exportPublicParams()
        with open(MASTER_SECRET_KEY_FILE, 'wb') as mskf:
            mskf.write(MASTER_SECRET_KEY)
        with open(MASTER_PUBLIC_KEY_FILE, 'wb') as mpkf:
            mpkf.write(MASTER_PUBLIC_KEY)
        MASTER_KEYS_GENERATED = datetime.datetime.now()
    except:
        app.logger.error("FATAL ERROR: ABORTING SERVER")
        app.logger.error("Unexpected error:", sys.exc_info()[0])
        exit()

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/abe/get_public_key')
def get_public_key():
    mpk_payload = {
        'generated_at': MASTER_KEYS_GENERATED,
        'updated_at': datetime.datetime.now(),
        'mpk': MASTER_PUBLIC_KEY.decode('UTF-8'),
        'abe_version': VERSION
    }
    return jsonify(mpk_payload)

@app.route('/abe/generate_userkey', methods=['POST'])
def generate_userkey():
    user_attrs = request.get_json()
    if user_attrs is not None:
        print(user_attrs)
    # userkey_generated_at = datetime.datetime.now()
    # userkey_payload = {
    #     'generated_at': userkey_generated_at,
    #     'updated_at': datetime.datetime.now(),
    #     'userkey': userkey.decode('UTF-8'),
    #     'abe_version': VERSION
    # }
    # return jsonify(userkey_payload)
    return {'msg': 'OK'}

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
