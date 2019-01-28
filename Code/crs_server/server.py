"""
Client Resource Server module
"""

from sys import exc_info
from os import urandom, path
from io import BytesIO
from datetime import datetime
import json
import requests
from werkzeug.utils import secure_filename
from flask import Flask, flash, request, redirect, render_template,\
url_for, send_file, jsonify, abort
from flask.logging import create_logger
from decrypt_encrypt_tools import create_cpabe_instance, process_key_decrypt
from download_upload_tools import filename_from_attachment, extract_policy
#pylint: disable=E0401
import pyopenabe

ENC_ALLOWED_EXTENSIONS = set(['jp2', 'jpg', 'png', 'svg', 'ics', 'ppt', 'pptx',
                              'xls', 'xlsx', 'doc', 'docx', 'txt', 'pdf', 'zip'])
DEC_ALLOWED_EXTENSIONS = set(['cpabe'])
KEY_ALLOWED_EXTENSIONS = set(['key'])

VERSION = 'v0.0.2'
RES_SERVER = 'http://localhost:5001'

MASTER_PUBLIC_KEY_FILE = 'master_public_key.key'
GLOBAL_ABE_ATTRS_FILE = 'global_attrs.config'

APP = Flask(__name__)
LOG = create_logger(APP)

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
    MASTER_KEY_UPDATED = datetime.fromtimestamp(path.getmtime(MASTER_PUBLIC_KEY_FILE))
    LOG.info("Collected master public key from config file.")
except EnvironmentError:
    try:
        MASTER_PUBLIC_KEY, MASTER_KEY_UPDATED = get_latest_mpk(MASTER_PUBLIC_KEY_FILE)
    except EnvironmentError:
        LOG.error("FATAL ERROR: ABORTING SERVER")
        LOG.error("Cannot run server without global attributes file: %s", MASTER_PUBLIC_KEY_FILE)
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
    GLOBAL_ABE_ATTRS_UPDATED = datetime.fromtimestamp(path.getmtime(GLOBAL_ABE_ATTRS_FILE))
    LOG.info("Collected attributes from config file.")
except EnvironmentError:
    try:
        GLOBAL_ABE_ATTRS, GLOBAL_ABE_ATTRS_JSON, GLOBAL_ABE_ATTRS_UPDATED \
            = get_latest_attributes(GLOBAL_ABE_ATTRS_FILE)
    except EnvironmentError:
        LOG.error("FATAL ERROR: ABORTING SERVER")
        LOG.error("Cannot run server without global attributes file: %s", GLOBAL_ABE_ATTRS_FILE)
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
def hello_world():
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
        return render_template('mpk_updated.html', updated=True,\
            mpk=MASTER_PUBLIC_KEY.decode('UTF-8'), mku=MASTER_KEY_UPDATED)
    return render_template('mpk_updated.html', updated=False,\
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
        return render_template('attrs_updated.html', updated=True, gaaj=GLOBAL_ABE_ATTRS_JSON,\
            gaau=GLOBAL_ABE_ATTRS_UPDATED)
    return render_template('attrs_updated.html', updated=False, gaaj=GLOBAL_ABE_ATTRS_JSON,\
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
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'info')
            return redirect(request.url)
        if file and allowed_file(file.filename, DEC_ALLOWED_EXTENSIONS):
            file.filename = secure_filename(file.filename)
            print(file.filename)
            files = {'file': (file.filename, file.read(), file.content_type)}
            res_server_res = requests.post(f'{RES_SERVER}/upload',\
                files=files, data={"author": author, "policy": policy})
            if res_server_res.status_code == 200:
                flash('successfully uploaded!', 'info')
                return redirect(url_for('get_all_filenames'), code=303)
        flash('Error with upload!', 'error')
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
        if 'file' not in request.files:
            flash('No file part', 'info')
            return redirect(request.url)
        if 'policy' not in request.form:
            flash('No policy provided!', 'info')
            return redirect(request.url)
        file = request.files['file']
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
                flash(f"PyOpenABEError: {err}", 'error')
                return render_template('encrypt.html')
            del openabe, cpabe
            file_filename += '.cpabe'
            return send_file(
                BytesIO(ct_file),
                mimetype='text/plain',
                as_attachment=True,
                attachment_filename=file_filename)
        flash('Error with encryption!', 'error')
    return render_template('encrypt.html')

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
        if 'file' not in request.files:
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
        file = request.files['file']
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
                flash(f"PyOpenABEError: {err}", 'error')
                return render_template('encrypt_upload.html')
            del openabe, cpabe
            file.filename += '.cpabe'
            files = {'file': (file.filename, ct_file, file.content_type)}
            res_server_res = requests.post(f'{RES_SERVER}/upload',\
                files=files, data={"author": author, "policy": policy})
            if res_server_res.status_code == 200:
                flash('successfully uploaded!', 'info')
                return redirect(url_for('get_all_filenames'), code=303)
        flash('Error with upload!', 'error')
    return render_template('encrypt_upload.html')

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
            attachment_filename=filename)
    flash('No file matching that name found', 'error')
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
        if 'enc_file' not in request.files:
            flash('No encrypted file provided!', 'info')
        elif 'user_key' not in request.files:
            flash('No user key provided!', 'info')
        else:
            enc_file = request.files['enc_file']
            user_key = request.files['user_key']
            # if user does not select file, browser also
            # submit an empty part without filename
            if enc_file.filename == '':
                flash('No encrypted file provided!', 'info')
            elif user_key.filename == '':
                flash('No user key provided!', 'info')
            elif enc_file and user_key and allowed_file(enc_file.filename, DEC_ALLOWED_EXTENSIONS)\
                and allowed_file(user_key.filename, KEY_ALLOWED_EXTENSIONS):
                file_bytes = enc_file.read()
                key_bytes, username = process_key_decrypt(user_key)
                if file_bytes is not None and key_bytes is not None:
                    openabe, cpabe = create_cpabe_instance(MASTER_PUBLIC_KEY)
                    cpabe.importUserKey(username, key_bytes)
                    try:
                        dec_file = cpabe.decrypt(username, file_bytes)
                    except pyopenabe.PyOpenABEError as err:
                        flash(f"Decryption of file failed: {err}", 'error')
                        dec_file = None
                    del openabe, cpabe
                    if dec_file is not None:
                        return send_file(
                            BytesIO(dec_file),
                            mimetype='text/plain',
                            as_attachment=True,
                            attachment_filename=enc_file.filename[:-6])
                flash('Decryption of file failed', 'error')
            else:
                flash('Issue with files! Make sure user key is a .key file and that the\
                    encrypted file is a .cpabe file!', 'error')
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
        # check if the post request has the file part
        if 'user_key' not in request.files:
            flash('No user key provided!', 'info')
        else:
            res_server_res = requests.get(f'{RES_SERVER}/download/{file_id}')
            if res_server_res.status_code != 200:
                abort(404)
            filename = filename_from_attachment(res_server_res)
            file_bytes = res_server_res.content
            if file_bytes is not None:
                user_key = request.files['user_key']
                # if user does not select key, browser may also
                # submit an empty part without filename
                if user_key.filename == '':
                    flash('No user key provided!', 'info')
                elif user_key:
                    key_bytes, username = process_key_decrypt(user_key)
                    openabe, cpabe = create_cpabe_instance(MASTER_PUBLIC_KEY)
                    print("created cpabe instance")
                    cpabe.importUserKey(username, key_bytes)
                    print("imported key!")
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
                        flash('Decryption of file failed', 'error')
                else:
                    flash('User Key not uploaded properly!', 'error')
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
    return render_template('search_files.html', files=None, search_term=search_term)

@APP.route('/files/search/<string:search_term>')
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
    response = requests.get(f'{RES_SERVER}/files/search/' + search_term + "?" + query_str)
    all_files = None
    if response.status_code == 200:
        res_dict = json.loads(response.content)
        all_files = res_dict['files']
    return render_template('search_files.html', files=all_files, search_term=search_term)

@APP.route('/files/fuzzy_search')
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
    return render_template('fuzzy_search_files.html', files=None, search_term=search_term)

@APP.route('/files/fuzzy_search/<string:search_term>')
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
    response = requests.get(f'{RES_SERVER}/files/fuzzy_search/' + search_term + "?" + query_str)
    all_files = None
    if response.status_code == 200:
        res_dict = json.loads(response.content)
        all_files = res_dict['files']
    return render_template('fuzzy_search_files.html', files=all_files, search_term=search_term)

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
