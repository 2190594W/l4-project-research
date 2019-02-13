#pylint: disable=C0302
"""
Client Resource Server module
"""

from sys import exc_info
from os import urandom, path
from io import BytesIO
from datetime import datetime
import json
import uuid
import requests
from werkzeug.utils import secure_filename
from flask import Flask, flash, request, redirect, render_template,\
    url_for, send_file, jsonify, abort
from flask.logging import create_logger
from user_class import User
from decrypt_encrypt_tools import create_cpabe_instance, process_key_decrypt
from download_upload_tools import filename_from_attachment, extract_policy, extract_user_attrs
from authentication_tools import is_safe_url, validate_passwd
#pylint: disable=E0401
import pyopenabe
import pymongo
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from argon2 import PasswordHasher, exceptions

ENC_ALLOWED_EXTENSIONS = set(['jp2', 'jpg', 'png', 'svg', 'ics', 'ppt', 'pptx',
                              'xls', 'xlsx', 'doc', 'docx', 'txt', 'pdf', 'zip'])
DEC_ALLOWED_EXTENSIONS = set(['cpabe'])
KEY_ALLOWED_EXTENSIONS = set(['key'])

VERSION = 'v0.0.3'
RES_SERVER = 'http://localhost:5001'

DB_HOST = "localhost"
DB_PORT = 27017

MASTER_PUBLIC_KEY_FILE = 'master_public_key.key'
GLOBAL_ABE_ATTRS_FILE = 'global_attrs.config'

CONNECTION = pymongo.MongoClient(
    DB_HOST, DB_PORT, uuidRepresentation='standard')
DB = CONNECTION.UserServer
DB.users.ensure_index('id', unique=True)
DB.users.ensure_index('username', unique=True)
ACCOUNT_DB = DB.users

LOGIN_MANAGER = LoginManager()

APP = Flask(__name__)
LOG = create_logger(APP)

LOGIN_MANAGER.init_app(APP)
LOGIN_MANAGER.session_protection = "strong"

PH = PasswordHasher()

@LOGIN_MANAGER.user_loader
def load_user(user_id):
    """Callback function for flask_login to retrieve a user object from session.

    Parameters
    ----------
    user_id : UUID
        UUID representing the `user_id` of the user.

    Returns
    -------
    User
        Returns instance of the User class with the retrieved details.

    """
    user = ACCOUNT_DB.find_one(
        {"id": uuid.UUID(user_id)},
        {"password_hash": 0, "_id": 0}
    )
    if user:
        return User(user["id"], user["username"], user["user_attrs"], user["user_key"])
    return None

@APP.route('/login', methods=['GET', 'POST'])
def login():
    """Login handler for authentication.
    Authenticates provided password via argon2 verification
    with password hash in local user accounts DB.
    Attached to '/login' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    if request.method == 'POST':
        if 'username' not in request.form:
            flash('No username provided', 'warning')
            return redirect(request.url)
        if 'passwd' not in request.form:
            flash('No password provided', 'warning')
            return redirect(request.url)
        username = request.form["username"]
        password = request.form["passwd"]
        if username is not None and password is not None:
            username = username.lower()
            passwd_hash = ACCOUNT_DB.find_one(
                {"username": username},
                {"password_hash":1, "_id":0}
            )
            try:
                ph_verify = PH.verify(passwd_hash["password_hash"], password)
            except exceptions.VerifyMismatchError:
                ph_verify = False
            except TypeError:
                ph_verify = False
            if ph_verify:
                user_record = ACCOUNT_DB.find_one(
                    {"username": username},
                    {"password_hash": 0, "_id": 0}
                )
                if user_record is not None:
                    user = User(user_record["id"], user_record["username"],
                                user_record["user_attrs"], user_record["user_key"])

                    login_user(user)
                    flash('Logged in successfully.', 'success')

                    next_loc = request.args.get('next')
                    if not is_safe_url(next_loc):
                        return abort(400)

                    return redirect(next_loc or url_for('index'))
                flash("There was an issue processing the login", "warning")
            flash("Username or password incorrect!", "warning")
            return render_template('login.html', username=username)
        flash("Username or password not provided", "warning")
    return render_template('login.html')

@APP.route('/register', methods=['GET', 'POST'])
#pylint: disable=R0911
def register():
    """Registration handler for authentication.
    Authenticates provided password via argon2 verification
    with password hash in local user accounts DB.
    Attached to '/register' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    if request.method == 'POST':
        if 'username' not in request.form:
            flash('No username provided', 'warning')
            return render_template('register.html')
        username = request.form["username"]
        if 'passwd' not in request.form:
            flash('No password provided', 'warning')
            return render_template('register.html', username=username)
        password = request.form["passwd"]
        if 'confirm_passwd' not in request.form:
            flash('No password confirmation provided', 'warning')
            return render_template('register.html', username=username)
        confirm_password = request.form["confirm_passwd"]
        if 'user_key' not in request.files:
            flash('No user key provided', 'warning')
            return render_template('register.html', username=username)
        user_key = request.files["user_key"]
        # if user does not select file, browser may also
        # submit an empty part without filename
        if user_key.filename == '':
            flash('No selected file', 'info')
            return render_template('register.html', username=username)
        if not validate_passwd(password):
            return render_template('register.html', username=username)
        if None not in (username, password, confirm_password, user_key):
            username = username.lower()
            if password != confirm_password:
                flash('Passwords do not match!', 'warning')
                return redirect(request.url)
            user_passwd_hash = PH.hash(password)
            key_bytes = user_key.read().strip()
            user_attrs = extract_user_attrs(key_bytes)
            user_id = uuid.uuid4()
            if user_passwd_hash and key_bytes and user_attrs and user_id:
                user_obj = {'id': user_id, 'username': username, 'user_key': key_bytes,
                            'password_hash': user_passwd_hash, 'user_attrs': user_attrs}
                ACCOUNT_DB.save(user_obj)

                flash('Registered successfully.', 'success')

                next_loc = request.args.get('next')
                if not is_safe_url(next_loc):
                    return abort(400)

                return redirect(next_loc or url_for('login'))
            flash("Failed to process registration! Please try again.", "warning")
            return render_template('register.html', username=username)
        flash("Username or password not provided", "warning")
    return render_template('register.html', username=None)

@APP.route("/logout")
@login_required
def logout():
    """Logout handler for authentication.
    Logs the user out and removes sessions.
    Attached to '/logout' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    logout_user()
    return redirect(url_for('index'))

try:
    with open('userkey.key', 'rb') as userkey:
        USERKEY = userkey.read().strip()
except EnvironmentError:
    LOG.error("No user key found!")
    exit()

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


def get_latest_mpk(mpk_f):
    """Collect latest Master Public Key (mpk) file from Resource Server.

    Parameters
    ----------
    mpk_f : string
        String representing mpk filename - `mpk_f`.

    Returns
    -------
    mpk : Bytes
        Bytes object representing mpk file contents.
    mku : Datetime
        Datetime object representing the last time MPK was updated.

    """
    response = requests.get(f'{RES_SERVER}/abe/latest_mpk')
    if response.status_code == 200:
        res_dict = json.loads(response.content)
        mpk = res_dict['mpk'].encode('UTF-8')
        with open(mpk_f, 'wb') as mpk_b:
            mpk_b.write(mpk)
        mku = datetime.now()
        LOG.info("DEV: Collected master public key from RES server.")
        return mpk, mku
    raise EnvironmentError('Unable to reach dev res server.')


try:
    with open(MASTER_PUBLIC_KEY_FILE, 'rb') as mpkf:
        MASTER_PUBLIC_KEY = mpkf.read()
    MASTER_KEY_UPDATED = datetime.fromtimestamp(
        path.getmtime(MASTER_PUBLIC_KEY_FILE))
    LOG.info("Collected master public key from config file.")
except EnvironmentError:
    try:
        MASTER_PUBLIC_KEY, MASTER_KEY_UPDATED = get_latest_mpk(
            MASTER_PUBLIC_KEY_FILE)
    except EnvironmentError:
        LOG.error("FATAL ERROR: ABORTING SERVER")
        LOG.error("Cannot run server without global attributes file: %s",
                  MASTER_PUBLIC_KEY_FILE)
        LOG.error("Unexpected error: %s", exc_info()[0])
        exit()


def get_latest_attributes(gaa_f):
    """Collect latest Global ABE Attributes (gaa) file from Resource Server.

    Parameters
    ----------
    gaa_f : string
        String representing gaa filename - `gaa_f`.

    Returns
    -------
    gaa : Bytes
        Bytes object representing gaa file contents.
    gaaj : string (JSON)
        JSON object representing gaa file contents and meta.
    gaau : Datetime
        Datetime object representing the last time GAA file was updated.

    """
    response = requests.get(f'{RES_SERVER}/abe/latest_attributes')
    if response.status_code == 200:
        res_dict = json.loads(response.content)
        gaa = res_dict['attributes']
        gaaj = json.dumps(gaa)
        with open(gaa_f, 'w') as gaa_b:
            gaa_b.write(gaaj)
        gaau = datetime.now()
        LOG.info("DEV: Collected attributes from RES server.")
        return gaa, gaaj, gaau
    raise EnvironmentError('Unable to reach dev res server.')


try:
    with open(GLOBAL_ABE_ATTRS_FILE, 'r') as gaaf:
        GLOBAL_ABE_ATTRS_JSON = gaaf.read()
    GLOBAL_ABE_ATTRS = json.loads(GLOBAL_ABE_ATTRS_JSON)
    GLOBAL_ABE_ATTRS_UPDATED = datetime.fromtimestamp(
        path.getmtime(GLOBAL_ABE_ATTRS_FILE))
    LOG.info("Collected attributes from config file.")
except EnvironmentError:
    try:
        GLOBAL_ABE_ATTRS, GLOBAL_ABE_ATTRS_JSON, GLOBAL_ABE_ATTRS_UPDATED \
            = get_latest_attributes(GLOBAL_ABE_ATTRS_FILE)
    except EnvironmentError:
        LOG.error("FATAL ERROR: ABORTING SERVER")
        LOG.error("Cannot run server without global attributes file: %s",
                  GLOBAL_ABE_ATTRS_FILE)
        LOG.error("Unexpected error: %s", exc_info()[0])
        exit()


def allowed_file(filename, allowed_extensions):
    """Small function to validate that a given filename ends with a valid extension.

    Parameters
    ----------
    filename : string
        String representing the `filename` to be checked.
    ALLOWED_EXTENSIONS : list
        List of allowed extensions to be compared `ALLOWED_EXTENSIONS`.

    Returns
    -------
    boolean
        Boolean value representing if file extension is allowed.

    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions


@APP.route('/')
def index():
    """Simple template generation for homepage/index of app.
    Attached to '/' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    return render_template('index.html')


@APP.route('/abe/check_mpk_updated')
def check_mpk_updated():
    """Checks if current stored MPK is up to date with Resource Server.
    Call on get_latest_mpk() to pull the latest MPK file and handle storage.
    Simple template generation for MPK updated status page of app.
    Attached to '/abe/check_mpk_updated' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    #pylint: disable=W0603
    global MASTER_PUBLIC_KEY, MASTER_KEY_UPDATED
    mpk2, mku2 = get_latest_mpk(MASTER_PUBLIC_KEY_FILE)
    if mpk2 != MASTER_PUBLIC_KEY:
        MASTER_PUBLIC_KEY = mpk2
        MASTER_KEY_UPDATED = mku2
        return render_template('mpk_updated.html', updated=True,
                               mpk=MASTER_PUBLIC_KEY.decode('UTF-8'), mku=MASTER_KEY_UPDATED)
    return render_template('mpk_updated.html', updated=False,
                           mpk=MASTER_PUBLIC_KEY, mku=MASTER_KEY_UPDATED)


@APP.route('/abe/latest_mpk_file')
def latest_mpk_file():
    """Route to allow end user to download copy of current MPK file.
    Pulls stored MPK value from memory and generates virtual file with
    BytesIO to send to user with flask Response.
    Attached to '/abe/latest_mpk_file' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from a generated BytesIO file.

    """
    return send_file(
        BytesIO(MASTER_PUBLIC_KEY),
        mimetype='text/plain',
        as_attachment=True,
        attachment_filename="master_public_key.key")


@APP.route('/abe/latest_mpk_json')
def latest_mpk_json():
    """Route to allow end user to download JSON object of current MPK.
    Pulls stored MPK value from memory and generates a dictionary structure
    before converting and sending as JSON response.
    Attached to '/abe/latest_mpk_json' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    JSON
        JSON payload representing current MPK.

    """
    mpk_payload = {
        'generated_at': MASTER_KEY_UPDATED,
        'updated_at': datetime.now(),
        'mpk': MASTER_PUBLIC_KEY.decode('UTF-8'),
        'abe_version': VERSION
    }
    return jsonify(mpk_payload)


@APP.route('/abe/check_attributes_updated')
def check_attributes_updated():
    """Checks if current stored GAA are up to date with Resource Server.
    GAA = Globale ABE Attributes.
    Call on get_latest_attributes() to pull the latest GAA file and handle storage.
    Simple template generation for GAA updated status page of app.
    Attached to '/abe/check_attributes_updated' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    #pylint: disable=W0603
    global GLOBAL_ABE_ATTRS, GLOBAL_ABE_ATTRS_JSON, GLOBAL_ABE_ATTRS_UPDATED
    gaa2, gaaj2, gaau2 = get_latest_attributes(GLOBAL_ABE_ATTRS_FILE)
    if gaa2 != GLOBAL_ABE_ATTRS:
        GLOBAL_ABE_ATTRS = gaa2
        GLOBAL_ABE_ATTRS_JSON = gaaj2
        GLOBAL_ABE_ATTRS_UPDATED = gaau2
        return render_template('attrs_updated.html', updated=True, gaaj=GLOBAL_ABE_ATTRS_JSON,
                               gaau=GLOBAL_ABE_ATTRS_UPDATED)
    return render_template('attrs_updated.html', updated=False, gaaj=GLOBAL_ABE_ATTRS_JSON,
                           gaau=GLOBAL_ABE_ATTRS_UPDATED)


@APP.route('/abe/latest_attributes_file')
def latest_attributes_file():
    """Route to allow end user to download copy of current GAA file.
    Pulls stored GAA value from memory and generates virtual file with
    BytesIO to send to user with flask Response.
    Attached to '/abe/latest_attributes_file' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from a generated BytesIO file.

    """
    return send_file(
        BytesIO(GLOBAL_ABE_ATTRS_JSON.encode('UTF-8')),
        mimetype='text/plain',
        as_attachment=True,
        attachment_filename="global_attrs.config")


@APP.route('/abe/latest_attributes_json')
def latest_attributes_json():
    """Route to allow end user to download JSON object of current GAA.
    Pulls stored GAA value from memory and generates a dictionary structure
    before converting and sending as JSON response.
    Attached to '/abe/latest_attributes_json' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    JSON
        JSON payload representing current GAA.

    """
    attributes_payload = {
        'generated_at': GLOBAL_ABE_ATTRS_UPDATED,
        'updated_at': datetime.now(),
        'attributes': GLOBAL_ABE_ATTRS,
        'abe_version': VERSION
    }
    return jsonify(attributes_payload)


@APP.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """If GET request, simple template generation for upload page of app.
    If POST request, handle uploading file in request to the Resource
    server, while validating file and filename.
    If successful, redirects to list of uploaded files.
    Attached to '/upload' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'info')
            return redirect(request.url)
        if 'author' not in request.form:
            flash('No author provided! File has been uploaded anonymously.', 'info')
            author = "Anonymous"
        else:
            author = request.form["author"]
        file = request.files['file']
        # if user does not select file, browser may also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'info')
            return redirect(request.url)
        if 'policy' not in request.form:
            flash('Policy not provided, attempted to extract from file.', 'info')
            policy = None
        else:
            policy = request.form["policy"]
        if policy is None or policy == "":
            try:
                policy = extract_policy(file.read())
                flash('Policy extraction successful.', 'info')
            except IndexError as err:
                flash('Policy extraction failed.', 'warning')
                LOG.error("IndexError occurred: %s", err)
                policy = "Unknown"
        if file and allowed_file(file.filename, DEC_ALLOWED_EXTENSIONS):
            file.filename = secure_filename(file.filename)
            print(file.filename)
            files = {'file': (file.filename, file.read(), file.content_type)}
            res_server_res = requests.post(f'{RES_SERVER}/upload',
                                           files=files, data={"author": author, "policy": policy})
            if res_server_res.status_code == 200:
                flash('successfully uploaded!', 'info')
                return redirect(url_for('get_all_filenames'), code=303)
        flash('Error with upload!', 'danger')
    return render_template('upload.html')


@APP.route('/encrypt', methods=['GET', 'POST'])
def encrypt_file():
    """View to encrypt a file for the user.
    Using a unencrypted file and a user-defined policy from
    the POST request, encrypts the file with CP-ABE.
    Attached to '/encrypt' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from a generated BytesIO file.

    """
    if request.method == 'POST':
        # check if the post request has the file part
        if 'enc_file' not in request.files:
            flash('No file part', 'info')
            return redirect(request.url)
        if 'policy' not in request.form:
            flash('No policy provided!', 'info')
            return redirect(request.url)
        file = request.files['enc_file']
        policy = request.form['policy']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'info')
            return redirect(request.url)
        if file and policy and allowed_file(file.filename, ENC_ALLOWED_EXTENSIONS):
            file_filename = secure_filename(file.filename)
            openabe, cpabe = create_cpabe_instance(MASTER_PUBLIC_KEY)
            try:
                ct_file = cpabe.encrypt(policy, file.read())
            except pyopenabe.PyOpenABEError as err:
                del openabe, cpabe
                flash(f"PyOpenABEError: {err}", 'danger')
                return render_template('encrypt.html', global_attrs=GLOBAL_ABE_ATTRS)
            del openabe, cpabe
            file_filename += '.cpabe'
            return send_file(
                BytesIO(ct_file),
                mimetype='text/plain',
                as_attachment=True,
                attachment_filename=file_filename)
        flash('Error with encryption!', 'danger')
    return render_template('encrypt.html', global_attrs=GLOBAL_ABE_ATTRS)


@APP.route('/encrypt_upload', methods=['GET', 'POST'])
def encrypt_upload_file():
    """View to encrypt and upload a file for the user.
    Using a unencrypted file and a user-defined policy from the
    POST request, encrypts the file with CP-ABE. The new encrypted
    ciphertext binary is then uploaded to the Resource Server
    Attached to '/encrypt_upload' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    if request.method == 'POST':
        # check if the post request has the file part
        if 'enc_file' not in request.files:
            flash('No file uploaded!', 'info')
            return redirect(request.url)
        if 'policy' not in request.form:
            flash('No policy provided!', 'info')
            return redirect(request.url)
        if 'author' not in request.form:
            flash('No author provided! File has been uploaded anonymously.', 'info')
            author = "Anonymous"
        else:
            author = request.form["author"]
        file = request.files['enc_file']
        policy = request.form['policy']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'info')
            return redirect(request.url)
        if file and policy and allowed_file(file.filename, ENC_ALLOWED_EXTENSIONS):
            file.filename = secure_filename(file.filename)
            openabe, cpabe = create_cpabe_instance(MASTER_PUBLIC_KEY)
            try:
                ct_file = cpabe.encrypt(policy, file.read())
            except pyopenabe.PyOpenABEError as err:
                del openabe, cpabe
                flash(f"PyOpenABEError: {err}", 'danger')
                return render_template('encrypt_upload.html', global_attrs=GLOBAL_ABE_ATTRS)
            del openabe, cpabe
            file.filename += '.cpabe'
            files = {'file': (file.filename, ct_file, file.content_type)}
            res_server_res = requests.post(f'{RES_SERVER}/upload',
                                           files=files, data={"author": author, "policy": policy})
            if res_server_res.status_code == 200:
                flash('successfully uploaded!', 'info')
                return redirect(url_for('get_all_filenames'), code=303)
        flash('Error with upload!', 'danger')
    return render_template('encrypt_upload.html', global_attrs=GLOBAL_ABE_ATTRS)


@APP.route('/download/<string:file_id>')
def download_file(file_id):
    """View to download a file for the user.
    Retrieves an encrypted file from the Resource Server,
    as defined by the provided file_id param.
    Attached to '/download/<file_id>' route by flask annotation.

    Parameters
    ----------
    file_id : string (UUID)
        String representing the UUID of the uploaded file `file_id`.


    Returns
    -------
    Response (flask)
        Generates flask Response object from a generated BytesIO file.

    """
    res_server_res = requests.get(f'{RES_SERVER}/download/{file_id}')
    filename = filename_from_attachment(res_server_res)
    if res_server_res.status_code == 200:
        return send_file(
            BytesIO(res_server_res.content),
            mimetype='text/plain',
            as_attachment=True,
            attachment_filename=filename if filename is not None else file_id + ".cpabe")
    flash('No file matching that name found', 'danger')
    return render_template('download_fail.html')


@APP.route('/decrypt', methods=['GET', 'POST'])
def decrypt_file():
    """View to decrypt a file for the user.
    Using an encrypted file and a user's key from
    the POST request, decrypts the file with CP-ABE.
    Attached to '/decrypt' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from a generated BytesIO file.

    """
    if request.method == 'POST':
        # check if the post request has the file part
        try:
            enc_file = request.files['enc_file']
            ef_filename = enc_file.filename
        except KeyError:
            flash('No encrypted file provided!', 'info')
            ef_filename = None
        if not current_user.is_authenticated:
            try:
                user_key = request.files['user_key']
                if user_key.filename == "":
                    raise KeyError("No key file")
                key_bytes, username = process_key_decrypt(user_key)
            except KeyError:
                flash('No user key provided!', 'info')
        else:
            key_bytes = current_user.user_key
            username = current_user.username
        if None not in (ef_filename, key_bytes, username):
            # if user does not select file, browser may also
            # submit an empty part without filename
            if allowed_file(ef_filename, DEC_ALLOWED_EXTENSIONS):
                file_bytes = enc_file.read()
                if file_bytes is not None:
                    openabe, cpabe = create_cpabe_instance(MASTER_PUBLIC_KEY)
                    cpabe.importUserKey(username, key_bytes)
                    try:
                        dec_file = cpabe.decrypt(username, file_bytes)
                    except pyopenabe.PyOpenABEError as err:
                        flash(f"Decryption of file failed: {err}", 'danger')
                        dec_file = None
                    del openabe, cpabe
                    if dec_file is not None:
                        ef_filename = ef_filename.split(".cpabe")[0]
                        ef_filename = ef_filename.split(" ")[0]
                        return send_file(
                            BytesIO(dec_file),
                            mimetype='text/plain',
                            as_attachment=True,
                            attachment_filename=ef_filename)
                flash('Decryption of file failed', 'danger')
            else:
                flash('Issue with files! Make sure user key is a .key file and that the\
                    encrypted file is a .cpabe file!', 'danger')
    return render_template('decrypt.html')


@APP.route('/download_decrypt/<string:file_id>', methods=['GET', 'POST'])
def download_decrypt_file(file_id):
    """View to download & decrypt a file for the user.
    Retrieves an encrypted file from the Resource Server,
    as defined by the provided file_id param and attempts to
    decrypt the file with the user's key, provided by POST request.
    Attached to '/download_decrypt/<file_id>' route by flask annotation.

    Parameters
    ----------
    file_id : string (UUID)
        String representing the UUID of the uploaded file `file_id`.


    Returns
    -------
    Response (flask)
        Generates flask Response object from a generated BytesIO file.

    """
    res_server_res = requests.get(f'{RES_SERVER}/file_meta/{file_id}')
    res_json_dict = json.loads(res_server_res.content)
    if request.method == 'POST':
        if not current_user.is_authenticated:
            try:
                user_key = request.files['user_key']
                if user_key.filename == "":
                    raise KeyError("No key file")
                key_bytes, username = process_key_decrypt(user_key)
            except KeyError:
                flash('No user key provided!', 'info')
        else:
            key_bytes = current_user.user_key
            username = current_user.username
        if None not in (key_bytes, username):
            res_server_res = requests.get(f'{RES_SERVER}/download/{file_id}')
            if res_server_res.status_code != 200:
                abort(404)
            filename = filename_from_attachment(res_server_res)
            file_bytes = res_server_res.content
            if file_bytes is not None:
                openabe, cpabe = create_cpabe_instance(MASTER_PUBLIC_KEY)
                cpabe.importUserKey(username, key_bytes)
                try:
                    dec_file = cpabe.decrypt(username, file_bytes)
                    del openabe, cpabe
                    return send_file(
                        BytesIO(dec_file),
                        mimetype='text/plain',
                        as_attachment=True,
                        attachment_filename=res_json_dict["filename"][:-6])
                except pyopenabe.PyOpenABEError as err:
                    del openabe, cpabe
                    LOG.error("PyOpenABE error: %s", err)
                    flash('Decryption of file failed', 'danger')
                else:
                    flash('User Key not uploaded properly!', 'danger')
        return render_template('download_decrypt.html', file=filename, error=True)
    return render_template('download_decrypt.html', filename=res_json_dict["filename"])


# TODO: This is a näive implementation. If there are too many files,
# the response would be massive, so paging would be needed here
@APP.route('/all_filenames')
def get_all_filenames():
    """Fetches list of uploaded filenames from Resource server and
    displays the returned list in a Jinja2 template.
    If no files retrieved, template explains this failure.
    Attached to '/all_filenames' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    response = requests.get(f'{RES_SERVER}/all_filenames')
    all_files = None
    if response.status_code == 200:
        res_dict = json.loads(response.content)
        all_files = res_dict['files']
    return render_template('all_files.html', files=all_files)


@APP.route('/files/search')
@login_required
def search_files_index():
    """Simple template to allow a user to enter their desired search
    query into a form (instead of URL).
    Attached to '/files/search' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    query_str = request.query_string.decode("utf-8")
    try:
        search_term = query_str.split("prev_query=")[1].split("&")[0]
    except IndexError:
        search_term = ""
    return render_template('search_files.html', searched=False,
                           files=None, search_term=search_term)


@APP.route('/files/search/<string:search_term>')
@login_required
def search_files(search_term):
    """Fetches list of uploaded filenames from Resource server and
    displays the returned list in a Jinja2 template. The provided
    search term is passed to the Resource server for the DB query.
    If no files retrieved, template explains this failure.
    Attached to '/files/search/<string:search_term>' route by flask annotation.

    Parameters
    ----------
    search_term : string
        String representing the user's desired `search_term`.

    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    query_str = request.query_string.decode("utf-8")
    response = requests.get(
        f'{RES_SERVER}/files/search/' + search_term + "?" + query_str)
    all_files = None
    if response.status_code == 200:
        print("success")
        res_dict = json.loads(response.content)
        all_files = res_dict['files']
        print(all_files)
    return render_template('search_files.html', searched=True,
                           files=all_files, search_term=search_term)


@APP.route('/files/fuzzy_search')
@login_required
def fuzzy_search_files_index():
    """Simple template to allow a user to enter their desired search
    query into a form (instead of URL).
    Attached to '/files/fuzzy_search' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    query_str = request.query_string.decode("utf-8")
    try:
        search_term = query_str.split("prev_query=")[1].split("&")[0]
    except IndexError:
        search_term = ""
    return render_template('fuzzy_search_files.html', searched=False,
                           files=None, search_term=search_term)


@APP.route('/files/fuzzy_search/<string:search_term>')
@login_required
def fuzzy_search_files(search_term):
    """Fetches list of uploaded filenames from Resource server and
    displays the returned list in a Jinja2 template. The provided
    search term is passed to the Resource server for a fuzzy string query.
    If no files retrieved, template explains this failure.
    Attached to '/files/fuzzy_search/<string:search_term>' route by flask annotation.

    Parameters
    ----------
    search_term : string
        String representing the user's desired `search_term`.

    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    query_str = request.query_string.decode("utf-8")
    response = requests.get(
        f'{RES_SERVER}/files/fuzzy_search/' + search_term + "?" + query_str)
    all_files = None
    if response.status_code == 200:
        res_dict = json.loads(response.content)
        all_files = res_dict['files']
    return render_template('fuzzy_search_files.html', searched=True,
                           files=all_files, search_term=search_term)


@APP.route('/extract_policy', methods=['GET', 'POST'])
@login_required
def extract_policy_view():
    """If GET request, simple template generation for page of app.
    If POST request, handle extracting the policy embedded
    in the uploaded file, while validating file and filename.
    If successful, generates page of extracted info.
    Attached to '/extract_policy' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    if request.method == 'POST':
        # check if the post request has the file part
        if 'enc_file' not in request.files:
            flash('No file part', 'info')
            return redirect(request.url)
        file = request.files['enc_file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'info')
            return redirect(request.url)
        try:
            extr_policy = extract_policy(file.read())
            if extr_policy != "Unknown":
                flash('Policy extraction successful.', 'success')
            return render_template('extract_policy.html', extr_policy=extr_policy)
        except IndexError as err:
            flash('Policy extraction failed.', 'warning')
            LOG.error("IndexError occurred: %s", err)
            extr_policy = "Unknown"
        flash('Error with file for extraction!', 'danger')
        return render_template('extract_policy.html', extr_policy=extr_policy)
    return render_template('extract_policy.html', extr_policy=None)

@APP.route('/extract_user_attrs', methods=['GET', 'POST'])
@login_required
def extract_user_attrs_view():
    """If GET request, simple template generation for page of app.
    If POST request, handle extracting the user attributes embedded
    in the uploaded file, while validating file and filename.
    If successful, generates page of extracted info.
    Attached to '/extract_user_attrs' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask)
        Generates flask Response object from Jinja2 template.

    """
    if request.method == 'POST':
        # check if the post request has the file part
        if 'user_key' not in request.files:
            flash('No file part', 'info')
            return redirect(request.url)
        file = request.files['user_key']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'info')
            return redirect(request.url)
        try:
            user_attrs = extract_user_attrs(file.read())
            if user_attrs != "Unknown":
                flash('User attributes extraction successful.', 'info')
            return render_template('extract_user_attrs.html',
                                   user_attrs=user_attrs.replace("|", "\n"))
        except IndexError as err:
            flash('User attributes extraction failed.', 'warning')
            LOG.error("IndexError occurred: %s", err)
            user_attrs = "Unknown"
        flash('Error with file for extraction!', 'danger')
        return render_template('extract_user_attrs.html', user_attrs=user_attrs)
    return render_template('extract_user_attrs.html', user_attrs=None)


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
