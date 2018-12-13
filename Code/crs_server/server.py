"""
Client Resource Server module
"""

from sys import exc_info
from os import urandom, path
from io import BytesIO
from datetime import datetime
import json
import requests
import pyopenabe
from werkzeug.utils import secure_filename
from flask import Flask, flash, request, redirect, render_template,\
url_for, send_from_directory, send_file, jsonify

ALLOWED_EXTENSIONS = set(['jp2', 'docx', 'txt', 'pdf'])

VERSION = 'v0.0.1'
RES_SERVER = "localhost:5001"

MASTER_PUBLIC_KEY_FILE = 'master_public_key.key'
GLOBAL_ABE_ATTRS_FILE = 'global_attrs.config'

USERNAME = "testuser"

try:
    with open('userkey.key', 'rb') as userkey:
        USERKEY = userkey.read().strip()
except:
    app.logger.error("No user key found!")
    exit()

app = Flask(__name__)

try:
    with open('session_secret.config', 'rb') as session_secret:
        app.secret_key = session_secret.read().strip()
        if len(app.secret_key) > 32:
            app.logger.info("Collected session secret from config file.")
        else:
            raise ValueError("Insufficient session secret provided")
except:
    app.logger.error("No sufficient session secret found, auto-generated random 64-bytes.")
    app.secret_key = urandom(64)

app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

def get_latest_mpk(mpkf):
    response = requests.get(f'http://{RES_SERVER}/abe/latest_mpk')
    if response.status_code == 200:
        res_dict = json.loads(response.content)
        mpk = res_dict['mpk'].encode('UTF-8')
        with open(mpkf, 'wb') as mpk_f:
            mpk_f.write(mpk)
        mku = datetime.now()
        app.logger.info("DEV: Collected master public key from RES server.")
        return mpk, mku
    else:
        raise Exception('Unable to reach dev res server.')

try:
    with open(MASTER_PUBLIC_KEY_FILE, 'rb') as mpkf:
        MASTER_PUBLIC_KEY = mpkf.read()
    MASTER_KEY_UPDATED = datetime.fromtimestamp(path.getmtime(MASTER_PUBLIC_KEY_FILE))
    app.logger.info("Collected master public key from config file.")
except:
    try:
        MASTER_PUBLIC_KEY, MASTER_KEY_UPDATED = get_latest_mpk(MASTER_PUBLIC_KEY_FILE)
    except:
        app.logger.error("FATAL ERROR: ABORTING SERVER")
        app.logger.error(f"Cannot run server without global attributes file: {MASTER_PUBLIC_KEY_FILE}")
        app.logger.error("Unexpected error:", exc_info()[0])
        exit()

def get_latest_attributes(gaaf):
    response = requests.get(f'http://{RES_SERVER}/abe/latest_attributes')
    if response.status_code == 200:
        res_dict = json.loads(response.content)
        gaa = res_dict['attributes']
        gaaj = json.dumps(gaa)
        with open(gaaf, 'w') as gaa_f:
            gaa_f.write(gaaj)
        gaau = datetime.now()
        app.logger.info("DEV: Collected attributes from RES server.")
        return gaa, gaaj, gaau
    else:
        raise Exception('Unable to reach dev res server.')

try:
    with open(GLOBAL_ABE_ATTRS_FILE, 'r') as gaaf:
        GLOBAL_ABE_ATTRS_JSON = gaaf.read()
    GLOBAL_ABE_ATTRS = json.loads(GLOBAL_ABE_ATTRS_JSON)
    GLOBAL_ABE_ATTRS_UPDATED = datetime.fromtimestamp(path.getmtime(GLOBAL_ABE_ATTRS_FILE))
    app.logger.info("Collected attributes from config file.")
except:
    try:
        GLOBAL_ABE_ATTRS, GLOBAL_ABE_ATTRS_JSON, GLOBAL_ABE_ATTRS_UPDATED = get_latest_attributes(GLOBAL_ABE_ATTRS_FILE)
    except:
        app.logger.error("FATAL ERROR: ABORTING SERVER")
        app.logger.error(f"Cannot run server without global attributes file: {GLOBAL_ABE_ATTRS_FILE}")
        app.logger.error("Unexpected error:", exc_info()[0])
        exit()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/abe/check_mpk_updated')
def check_mpk_updated():
    global MASTER_PUBLIC_KEY, MASTER_KEY_UPDATED
    mpk2, mku2 = get_latest_mpk(MASTER_PUBLIC_KEY_FILE)
    if mpk2 != MASTER_PUBLIC_KEY:
        MASTER_PUBLIC_KEY = mpk2
        MASTER_KEY_UPDATED = mku2
        return render_template('mpk_updated.html', updated=True, mpk=MASTER_PUBLIC_KEY.decode('UTF-8'), mku=MASTER_KEY_UPDATED)
    return render_template('mpk_updated.html', updated=False, mpk=MASTER_PUBLIC_KEY, mku=MASTER_KEY_UPDATED)

@app.route('/abe/latest_mpk_file')
def latest_mpk_file():
    return send_file(
        BytesIO(MASTER_PUBLIC_KEY),
        mimetype='text/plain',
        as_attachment=True,
        attachment_filename="master_public_key.key")

@app.route('/abe/latest_mpk_json')
def latest_mpk_json():
    mpk_payload = {
        'generated_at': MASTER_KEY_UPDATED,
        'updated_at': datetime.now(),
        'mpk': MASTER_PUBLIC_KEY.decode('UTF-8'),
        'abe_version': VERSION
    }
    return jsonify(mpk_payload)

@app.route('/abe/check_attributes_updated')
def check_attributes_updated():
    global GLOBAL_ABE_ATTRS, GLOBAL_ABE_ATTRS_JSON, GLOBAL_ABE_ATTRS_UPDATED
    gaa2, gaaj2, gaau2 = get_latest_attributes(GLOBAL_ABE_ATTRS_FILE)
    if gaa2 != GLOBAL_ABE_ATTRS:
        GLOBAL_ABE_ATTRS = gaa2
        GLOBAL_ABE_ATTRS_JSON = gaaj2
        GLOBAL_ABE_ATTRS_UPDATED = gaau2
        return render_template('attrs_updated.html', updated=True, gaaj=GLOBAL_ABE_ATTRS_JSON, gaau=GLOBAL_ABE_ATTRS_UPDATED)
    return render_template('attrs_updated.html', updated=False, gaaj=GLOBAL_ABE_ATTRS_JSON, gaau=GLOBAL_ABE_ATTRS_UPDATED)


@app.route('/abe/latest_attributes_file')
def latest_attributes_file():
    return send_file(
        BytesIO(GLOBAL_ABE_ATTRS_JSON.encode('UTF-8')),
        mimetype='text/plain',
        as_attachment=True,
        attachment_filename="global_attrs.config")

@app.route('/abe/latest_attributes_json')
def latest_attributes_json():
    attributes_payload = {
        'generated_at': GLOBAL_ABE_ATTRS_UPDATED,
        'updated_at': datetime.now(),
        'attributes': GLOBAL_ABE_ATTRS,
        'abe_version': VERSION
    }
    return jsonify(attributes_payload)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'info')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'info')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            files = {'file': file}
            res_server_res = requests.post(f'http://{RES_SERVER}/upload', files=files)
            if res_server_res.status_code == 200:
                flash('successfully uploaded!', 'info')
                return redirect(url_for('get_all_filenames'))
        flash('Error with upload!', 'error')
    return render_template('upload.html')

@app.route('/encrypt_upload', methods=['GET', 'POST'])
def encrypt_upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'info')
            return redirect(request.url)
        file = request.files['file']
        policy = request.form['policy']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'info')
            return redirect(request.url)
        if file and policy and allowed_file(file.filename):
            openabe = pyopenabe.PyOpenABE()
            cpabe = openabe.CreateABEContext("CP-ABE")
            cpabe.importPublicParams(MASTER_PUBLIC_KEY)
            cpabe.importUserKey(USERNAME, USERKEY)
            ct_file = cpabe.encrypt(policy, file.read())
            file.filename += '.cpabe'
            files = {'file': (file.filename, ct_file, file.content_type)}
            res_server_res = requests.post(f'http://{RES_SERVER}/upload', files=files)
            if res_server_res.status_code == 200:
                flash('successfully uploaded!', 'info')
                return redirect(url_for('get_all_filenames'))
        flash('Error with upload!', 'error')
    return render_template('encrypt_upload.html')


@app.route('/download/<filename>')
def uploaded_file(filename):
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], filename)

# TODO: This is a näive implementation. If there are too many files,
# the response would be massive, so paging would be needed here
@app.route('/all_filenames')
def get_all_filenames():
    response = requests.get(f'http://{RES_SERVER}/all_filenames')
    all_files = None
    if response.status_code == 200:
        res_dict = json.loads(response.content)
        all_files = res_dict['files']
    return render_template('all_files.html', files=all_files)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
