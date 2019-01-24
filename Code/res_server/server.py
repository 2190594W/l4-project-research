"""
Resource Server module
"""

from sys import exc_info
from os import urandom, path, walk, stat
from datetime import datetime
import uuid
import json
import requests
from flask import Flask, flash, request, redirect, render_template,\
url_for, send_from_directory, jsonify
from flask.logging import create_logger
from werkzeug.utils import secure_filename
import pymongo

CONNECTION = pymongo.MongoClient('localhost', 27017, uuidRepresentation='standard')
DB = CONNECTION.ResourceServer
DB.resource_meta.ensure_index('id', unique=True)
DB.resource_meta.ensure_index('filename')
META_DB = DB.resource_meta

UPLOAD_FOLDER = '/tmp/flask/file/uploads'
ALLOWED_EXTENSIONS = set(['cpabe'])

VERSION = 'v0.0.2'

MASTER_PUBLIC_KEY_FILE = 'master_public_key.key'

GLOBAL_ABE_ATTRS_FILE = 'global_attrs.config'

APP = Flask(__name__)
LOG = create_logger(APP)

try:
    with open('session_secret.config', 'rb') as session_secret:
        APP.secret_key = session_secret.read().strip()
        if len(APP.secret_key) > 32:
            LOG.info("Collected session secret from config file.")
        else:
            raise ValueError("Insufficient session secret provided")
except EnvironmentError:
    LOG.error("No sufficient session secret found, auto-generated random 64-bytes.")
    APP.secret_key = urandom(64)

APP.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
APP.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

try:
    with open(MASTER_PUBLIC_KEY_FILE, 'rb') as mpkf:
        MASTER_PUBLIC_KEY = mpkf.read()
    MASTER_KEY_UPDATED = datetime.fromtimestamp(path.getmtime(MASTER_PUBLIC_KEY_FILE))
    LOG.info("Collected master public key from config file.")
except EnvironmentError:
    try:
        response = requests.get('http://localhost:5000/abe/get_public_key')
        if response.status_code == 200:
            res_dict = json.loads(response.content)
            MASTER_PUBLIC_KEY = res_dict['mpk'].encode('UTF-8')
            with open(MASTER_PUBLIC_KEY_FILE, 'wb') as mpkf:
                mpkf.write(MASTER_PUBLIC_KEY)
            MASTER_KEY_UPDATED = datetime.now()
            LOG.info("DEV: Collected master public key from MSK server.")
        else:
            raise Exception('Unable to reach dev msk server.')
    except EnvironmentError:
        LOG.error("FATAL ERROR: ABORTING SERVER")
        LOG.error("Cannot run server without global attributes file: %s", MASTER_PUBLIC_KEY_FILE)
        LOG.error("Unexpected error: %s", exc_info()[0])
        exit()

try:
    with open(GLOBAL_ABE_ATTRS_FILE, 'r') as gaaf:
        GLOBAL_ABE_ATTRS_JSON = gaaf.read()
    GLOBAL_ABE_ATTRS = json.loads(GLOBAL_ABE_ATTRS_JSON)
    GLOBAL_ABE_ATTRS_UPDATED = datetime.fromtimestamp(path.getmtime(GLOBAL_ABE_ATTRS_FILE))
    LOG.info("Collected attributes from config file.")
except EnvironmentError:
    try:
        response = requests.get('http://localhost:5000/abe/get_attributes')
        if response.status_code == 200:
            res_dict = json.loads(response.content)
            GLOBAL_ABE_ATTRS = res_dict['attributes']
            GLOBAL_ABE_ATTRS_JSON = json.dumps(GLOBAL_ABE_ATTRS)
            with open(GLOBAL_ABE_ATTRS_FILE, 'w') as gaaf:
                gaaf.write(GLOBAL_ABE_ATTRS_JSON)
            GLOBAL_ABE_ATTRS_UPDATED = datetime.now()
            LOG.info("DEV: Collected attributes from MSK server.")
        else:
            raise Exception('Unable to reach dev msk server.')
    except EnvironmentError:
        LOG.error("FATAL ERROR: ABORTING SERVER")
        LOG.error("Cannot run server without global attributes file %s", GLOBAL_ABE_ATTRS_FILE)
        LOG.error("Unexpected error: %s", exc_info()[0])
        exit()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@APP.route('/')
def hello_world():
    return render_template('index.html')

@APP.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        if 'author' not in request.form:
            flash('No author provided! File will be uploaded anonymously.', 'info')
            author = "Anonymous"
        else:
            author = request.form["author"]
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            new_filename = uuid.uuid4()
            file_path = path.join(APP.config['UPLOAD_FOLDER'], str(new_filename) + ".cpabe")
            try:
                file.save(file_path)
                file_obj = {'id': str(new_filename), 'filename': file.filename,\
                    'mimetype': file.mimetype, 'content-type': file.content_type,\
                    'content-length': file.content_length, 'author': author,\
                    'uploader': author, 'filesize': stat(file_path).st_size}
                try:
                    with open(file_path[:-5] + 'meta', 'w') as file_meta:
                        file_meta.write(json.dumps(file_obj))
                    file_obj['id'] = new_filename
                    META_DB.save(file_obj)
                    flash('successfully uploaded!')
                except EnvironmentError:
                    flash('Failed to create .meta file correctly!', 'error')
                return redirect(url_for('get_all_filenames'), code=303)
            except EnvironmentError:
                flash('Failed to write .cpabe file correctly!', 'error')
        flash('Error with upload!', 'error')
    return render_template('upload.html')


@APP.route('/download/<filename>')
def uploaded_file(filename):
    return send_from_directory(
        APP.config['UPLOAD_FOLDER'], filename)

# TODO: This is a näive implementation. If there are too many files,
# the response would be massive, so paging would be needed here
@APP.route('/all_filenames')
def get_all_filenames():
    all_files = []
    for root, dirs, files in walk(APP.config['UPLOAD_FOLDER']):
        all_files.extend(files)
    filenames_payload = {
        'files': all_files,
        'updated_at': datetime.now(),
        'abe_version': VERSION
    }
    return jsonify(filenames_payload)

@APP.route('/abe/latest_mpk')
def get_latest_mpk():
    mpk_payload = {
        'generated_at': MASTER_KEY_UPDATED,
        'updated_at': datetime.now(),
        'mpk': MASTER_PUBLIC_KEY.decode('UTF-8'),
        'abe_version': VERSION
    }
    return jsonify(mpk_payload)

@APP.route('/abe/latest_attributes')
def get_latest_attributes():
    attributes_payload = {
        'generated_at': GLOBAL_ABE_ATTRS_UPDATED,
        'updated_at': datetime.now(),
        'attributes': GLOBAL_ABE_ATTRS,
        'abe_version': VERSION
    }
    return jsonify(attributes_payload)

@APP.errorhandler(404)
def page_not_found(error):
    """404 HTTP error handler.
    Attached by flask annotation to handle all 404 errors.

    Parameters
    ----------
    error : string
        String representation of HTTP `error`.

    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    template_error = None
    if APP.env == 'development':
        template_error = error
    else:
        print(error)
    return render_template('404.html', error=template_error), 404
