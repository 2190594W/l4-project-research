"""
Resource Server module
"""

from sys import exc_info
from os import urandom, path, walk
from datetime import datetime
import json
import requests
from flask import Flask, flash, request, redirect, render_template,\
url_for, send_from_directory, jsonify
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/tmp/flask/file/uploads'
ALLOWED_EXTENSIONS = set(['cpabe'])

VERSION = 'v0.0.1'

MASTER_PUBLIC_KEY_FILE = 'master_public_key.key'

GLOBAL_ABE_ATTRS_FILE = 'global_attrs.config'

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
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

try:
    with open(MASTER_PUBLIC_KEY_FILE, 'rb') as mpkf:
        MASTER_PUBLIC_KEY = mpkf.read()
    MASTER_KEY_UPDATED = datetime.fromtimestamp(path.getmtime(MASTER_PUBLIC_KEY_FILE))
    app.logger.info("Collected master public key from config file.")
except:
    try:
        response = requests.get('http://localhost:5000/abe/get_public_key')
        if response.status_code == 200:
            res_dict = json.loads(response.content)
            MASTER_PUBLIC_KEY = res_dict['mpk'].encode('UTF-8')
            with open(MASTER_PUBLIC_KEY_FILE, 'wb') as mpkf:
                mpkf.write(MASTER_PUBLIC_KEY)
            MASTER_KEY_UPDATED = datetime.now()
            app.logger.info("DEV: Collected master public key from MSK server.")
        else:
            raise Exception('Unable to reach dev msk server.')
    except:
        app.logger.error("FATAL ERROR: ABORTING SERVER")
        app.logger.error(f"Cannot run server without global attributes file: {MASTER_PUBLIC_KEY_FILE}")
        app.logger.error("Unexpected error:", exc_info()[0])
        exit()

try:
    with open(GLOBAL_ABE_ATTRS_FILE, 'r') as gaaf:
        GLOBAL_ABE_ATTRS_JSON = gaaf.read()
    GLOBAL_ABE_ATTRS = json.loads(GLOBAL_ABE_ATTRS_JSON)
    GLOBAL_ABE_ATTRS_UPDATED = datetime.fromtimestamp(path.getmtime(GLOBAL_ABE_ATTRS_FILE))
    app.logger.info("Collected attributes from config file.")
except:
    try:
        response = requests.get('http://localhost:5000/abe/get_attributes')
        if response.status_code == 200:
            res_dict = json.loads(response.content)
            GLOBAL_ABE_ATTRS = res_dict['attributes']
            GLOBAL_ABE_ATTRS_JSON = json.dumps(GLOBAL_ABE_ATTRS)
            with open(GLOBAL_ABE_ATTRS_FILE, 'w') as gaaf:
                gaaf.write(GLOBAL_ABE_ATTRS_JSON)
            GLOBAL_ABE_ATTRS_UPDATED = datetime.now()
            app.logger.info("DEV: Collected attributes from MSK server.")
        else:
            raise Exception('Unable to reach dev msk server.')
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

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        print(file.filename)
        print(file.content_type)
        if file and allowed_file(file.filename):
            flash('successfully uploaded!')
            filename = secure_filename(file.filename)
            file.save(path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file',
                                    filename=filename))
        flash('Error with upload!', 'error')
    return render_template('upload.html')


@app.route('/download/<filename>')
def uploaded_file(filename):
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], filename)

# TODO: This is a näive implementation. If there are too many files,
# the response would be massive, so paging would be needed here
@app.route('/all_filenames')
def get_all_filenames():
    all_files = []
    for root, dirs, files in walk(app.config['UPLOAD_FOLDER']):
        all_files.extend(files)
    filenames_payload = {
        'files': all_files,
        'updated_at': datetime.now(),
        'abe_version': VERSION
    }
    return jsonify(filenames_payload)

@app.route('/abe/latest_mpk')
def get_latest_mpk():
    mpk_payload = {
        'generated_at': MASTER_KEY_UPDATED,
        'updated_at': datetime.now(),
        'mpk': MASTER_PUBLIC_KEY.decode('UTF-8'),
        'abe_version': VERSION
    }
    return jsonify(mpk_payload)

@app.route('/abe/latest_attributes')
def get_latest_attributes():
    attributes_payload = {
        'generated_at': GLOBAL_ABE_ATTRS_UPDATED,
        'updated_at': datetime.now(),
        'attributes': GLOBAL_ABE_ATTRS,
        'abe_version': VERSION
    }
    return jsonify(attributes_payload)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
