"""
Resource Server module
"""

from sys import exc_info
from os import path, stat, urandom
from datetime import datetime
import uuid
import json
import requests
from flask import Flask, flash, request, redirect, render_template,\
    url_for, send_from_directory, jsonify, abort
from flask.logging import create_logger
#pylint: disable=E0401
import pymongo
from fuzzywuzzy import process

DB_HOST = "localhost"
DB_PORT = 27017

UPLOAD_FOLDER = '/tmp/flask/file/uploads'
ALLOWED_EXTENSIONS = set(['cpabe'])

VERSION = 'v0.0.3'
MK_SERVER = 'http://localhost:5000'

MASTER_PUBLIC_KEY_FILE = 'master_public_key.key'

GLOBAL_ABE_ATTRS_FILE = 'global_attrs.config'

CONNECTION = pymongo.MongoClient(
    DB_HOST, DB_PORT, uuidRepresentation='standard')
DB = CONNECTION.ResourceServer
DB.resource_meta.ensure_index('id', unique=True)
DB.resource_meta.ensure_index(
    [('search_filename', pymongo.TEXT)], default_language='english')
META_DB = DB.resource_meta

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


def update_mpk_file(mk_server, mpk_file_path):
    """Function to process updating the given MASTER PUBLIC KEY (MPK)
    file with the up-to-date values retrieved from the given MK SERVER address.

    Parameters
    ----------
    mk_server : string
        String representing the address of the `mk_server`.
    mpk_file_path : string
        String representing the path of the MPK file to update `mpk_file_path`.

    Returns
    -------
    Bytes, datetime
        Returns:
            Bytes object representing the current MPK retrieved.
            Datetime object representing the time the MPK was retrieved.

    """
    mpk_res = requests.get(f'{mk_server}/abe/get_public_key')
    mpk_u = datetime.now()
    if mpk_res.status_code == 200:
        mpk_res_dict = json.loads(mpk_res.content)
        mpk = mpk_res_dict['mpk'].encode('UTF-8')
        with open(mpk_file_path, 'wb') as mpk_f:
            mpk_f.write(mpk)
        LOG.info("DEV: Collected master public key from MSK server.")
        return mpk, mpk_u
    raise EnvironmentError('Unable to reach dev msk server.')


try:
    with open(MASTER_PUBLIC_KEY_FILE, 'rb') as mpkf:
        MASTER_PUBLIC_KEY = mpkf.read()
    MASTER_KEY_UPDATED = datetime.fromtimestamp(
        path.getmtime(MASTER_PUBLIC_KEY_FILE))
    LOG.info("Collected master public key from config file.")
except EnvironmentError:
    try:
        MASTER_PUBLIC_KEY, MASTER_KEY_UPDATED = update_mpk_file(
            MK_SERVER, MASTER_PUBLIC_KEY_FILE)
    except EnvironmentError:
        LOG.error("FATAL ERROR: ABORTING SERVER")
        LOG.error("Cannot run server without global attributes file: %s",
                  MASTER_PUBLIC_KEY_FILE)
        LOG.error("Unexpected error: %s", exc_info()[0])
        exit()


def update_gaa_file(mk_server, gaa_file_path):
    """Function to process updating the given GLOBAL ABE ATTRS (GAA)
    file with the up-to-date values retrieved from the given MK SERVER address.

    Parameters
    ----------
    mk_server : string
        String representing the address of the `mk_server`.
    gaa_file_path : string
        String representing the path of the GAA file to update `gaa_file_path`.

    Returns
    -------
    Dict, string, datetime
        Returns:
            Dictionary object representing the current GAA retrieved.
            String representing the JSON encoded GAA.
            Datetime object representing the time the GAA were retrieved.

    """
    gaa_res = requests.get(f'{mk_server}/abe/get_attributes')
    gaa_u = datetime.now()
    if gaa_res.status_code == 200:
        gaa_res_dict = json.loads(gaa_res.content)
        gaa = gaa_res_dict['attributes']
        gaa_j = json.dumps(gaa)
        with open(gaa_file_path, 'w') as gaa_f:
            gaa_f.write(gaa_j)
        LOG.info("DEV: Collected attributes from MSK server.")
        return gaa, gaa_j, gaa_u
    raise EnvironmentError('Unable to reach dev msk server.')


try:
    with open(GLOBAL_ABE_ATTRS_FILE, 'r') as gaaf:
        GLOBAL_ABE_ATTRS_JSON = gaaf.read()
    GLOBAL_ABE_ATTRS = json.loads(GLOBAL_ABE_ATTRS_JSON)
    GLOBAL_ABE_ATTRS_UPDATED = datetime.fromtimestamp(
        path.getmtime(GLOBAL_ABE_ATTRS_FILE))
    LOG.info("Collected attributes from config file.")
except EnvironmentError:
    try:
        GLOBAL_ABE_ATTRS, GLOBAL_ABE_ATTRS_JSON, GLOBAL_ABE_ATTRS_UPDATED = \
            update_gaa_file(MK_SERVER, GLOBAL_ABE_ATTRS_FILE)
    except EnvironmentError:
        LOG.error("FATAL ERROR: ABORTING SERVER")
        LOG.error("Cannot run server without global attributes file %s",
                  GLOBAL_ABE_ATTRS_FILE)
        LOG.error("Unexpected error: %s", exc_info()[0])
        exit()


def allowed_file(filename):
    """Small function to validate that a given filename ends with a valid extension.

    Parameters
    ----------
    filename : string
        String representing the `filename` to be checked.

    Returns
    -------
    boolean
        Boolean value representing if file extension is allowed.

    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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
            flash('No file part')
            return redirect(request.url)
        if 'author' not in request.form:
            flash('No author provided! File will be uploaded anonymously.', 'info')
            author = "Anonymous"
        else:
            author = request.form["author"]
        if 'policy' not in request.form:
            flash(
                'No policy provided for metadata! File will be uploaded without.', 'info')
            policy = None
        else:
            policy = request.form["policy"]
        file = request.files['file']
        # if user does not select file, browser also
        # may submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            new_filename = uuid.uuid4()
            file_path = path.join(
                APP.config['UPLOAD_FOLDER'], str(new_filename) + ".cpabe")
            try:
                file.save(file_path)
                uploaded_at = datetime.now()
                file_obj = {'id': str(new_filename), 'filename': file.filename,
                            'search_filename': file.filename.replace("_", "~"),
                            'mimetype': file.mimetype, 'content-type': file.content_type,
                            'content-length': file.content_length, 'author': author,
                            'uploader': author, 'filesize': stat(file_path).st_size,
                            'uploaded_at': str(uploaded_at), "policy": policy}
                try:
                    with open(file_path[:-5] + 'meta', 'w') as file_meta:
                        file_meta.write(json.dumps(file_obj))
                    file_obj['id'] = new_filename
                    file_obj['uploaded_at'] = uploaded_at
                    META_DB.save(file_obj)
                    flash('successfully uploaded!')
                except EnvironmentError:
                    flash('Failed to create .meta file correctly!', 'error')
                return redirect(url_for('get_all_filenames'), code=303)
            except EnvironmentError:
                flash('Failed to write .cpabe file correctly!', 'error')
        flash('Error with upload!', 'error')
    return render_template('upload.html')


@APP.route('/download/<string:file_id>')
def download_cpabe_file(file_id):
    """View to download an encrypted file for the user.
    Retrieves an encrypted file from the uploads directory,
    as defined by the provided file_id param.
    Attached to '/download/<file_id>' route by flask annotation.

    Parameters
    ----------
    file_id : string (UUID)
        String representing the UUID of the uploaded file `file_id`.


    Returns
    -------
    Response (flask)
        Generates flask Response object from a file retrieved from directory.

    """
    file_obj = META_DB.find_one({"id": uuid.UUID(file_id)}, {"filename"})
    if file_obj is not None:
        filename = file_obj["filename"]
        if not filename:
            filename = file_id + ".cpabe"
    try:
        return send_from_directory(
            APP.config['UPLOAD_FOLDER'], file_id + ".cpabe",
            as_attachment=True, attachment_filename=filename)
    except EnvironmentError:
        abort(404)


@APP.route('/download_meta/<string:file_id>')
def download_meta_file(file_id):
    """View to download a metadata file for the user.
    Retrieves a metadata file from the uploads directory,
    as defined by the provided file_id param.
    Attached to '/download/<file_id>' route by flask annotation.

    Parameters
    ----------
    file_id : string (UUID)
        String representing the UUID of the metadata file `file_id`.


    Returns
    -------
    Response (flask)
        Generates flask Response object from a file retrieved from directory.

    """
    file_obj = META_DB.find_one({"id": uuid.UUID(file_id)}, {"filename"})
    if file_obj is not None:
        filename = file_obj["filename"]
        if filename:
            filename = filename[:-5] + "meta"
        else:
            filename = file_id + ".meta"
    try:
        return send_from_directory(
            APP.config['UPLOAD_FOLDER'], file_id + ".meta",
            as_attachment=True, attachment_filename=filename)
    except EnvironmentError:
        abort(404)


@APP.route('/file_meta/<string:file_id>')
def get_file_meta(file_id):
    """View to return the metadata for a file.
    Retrieves the metadata of a file from the resource DB,
    as defined by the provided file_id param.
    Attached to '/file_meta/<file_id>' route by flask annotation.

    Parameters
    ----------
    file_id : string (UUID)
        String representing the UUID of the metadata file `file_id`.

    Returns
    -------
    Response (flask - JSON)
        Generates flask Response object by converting dict to JSON.

    """
    try:
        file_obj = META_DB.find_one(
            {"id": uuid.UUID(file_id)}, {"_id": 0, "id": 0})
    except ValueError:
        return abort(404)
    if file_obj is not None:
        return jsonify(file_obj)
    return abort(404)


# TODO: This is a näive implementation. If there are too many files,
# the response would be massive, so paging would be needed here
@APP.route('/all_filenames')
def get_all_filenames():
    """Fetches list of uploaded filenames from resource DB and
    structures the returned list in JSON object.
    Attached to '/all_filenames' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask - JSON)
        Generates flask Response object by converting dict to JSON.

    """
    all_files = []
    for resource in META_DB.find({}, {"id", "filename"}):
        all_files.append(
            {"id": resource["id"], "filename": resource["filename"]})
    filenames_payload = {
        'files': all_files,
        'updated_at': datetime.now(),
        'abe_version': VERSION
    }
    return jsonify(filenames_payload)


@APP.route('/files/search/<string:search_term>')
def search_files(search_term):
    """Fetches list of uploaded filenames from resource DB that meet the
    provided search term and structures the returned list as a JSON object.
    Attached to '/files/search/<string:search_term>' route by flask annotation.

    Parameters
    ----------
    search_term : string
        String representing the user's desired `search_term`.

    Returns
    -------
    Response (flask - JSON)
        Generates flask Response object by converting dict to JSON.

    """
    err_msg = None
    limit_query = request.query_string.decode("utf-8")
    try:
        search_limit = int(limit_query[6:]) if limit_query != "" else 25
        if search_limit > 200:
            err_msg = \
                "Limit too high (>200)! Not applied.\nLimited to 25 items as default."
            search_limit = 25
    except ValueError:
        err_msg = \
            "Limit has bad format! Not applied to fuzzy search.\nLimited to 25 items as default."
        search_limit = 25
    all_files = []
    for resource in META_DB.find(
            {"$text": {"$search": search_term}},
            {"score": {"$meta": "textScore"}, "id": 1, "filename": 1}
    ).sort([("score", {"$meta": "textScore"})]).limit(search_limit):
        all_files.append({
            "id": str(resource["id"]),
            "filename": resource["filename"],
            "search_score": resource["score"]
        })
    filenames_payload = {
        'files': all_files,
        'updated_at': datetime.now(),
        'abe_version': VERSION
    }
    if err_msg:
        filenames_payload['err_msg'] = err_msg
    return jsonify(filenames_payload)


@APP.route('/files/fuzzy_search/<string:search_term>')
def fuzzy_search_files(search_term):
    """Fetches list of uploaded filenames from resource DB and
    structures the returned list in JSON object. Applies a fuzzy
    search algorithm on returned values to match search term.
    Attached to '/files/fuzzy_search/<string:search_term>' route by flask annotation.

    Parameters
    ----------
    search_term : string
        String representing the user's desired `search_term`.

    Returns
    -------
    Response (flask - JSON)
        Generates flask Response object by converting dict to JSON.

    """
    err_msg = None
    limit_query = request.query_string.decode("utf-8")
    try:
        fuzzy_limit = int(limit_query[6:]) if limit_query != "" else 25
        if fuzzy_limit > 200:
            err_msg = \
                "Limit too high (>200)! Not applied.\nLimited to 25 items as default."
            fuzzy_limit = 25
    except ValueError:
        err_msg = \
            "Limit has bad format! Not applied to fuzzy search.\nLimited to 25 items as default."
        fuzzy_limit = 25
    all_files = {}
    for resource in META_DB.find({}, {"id", "filename"}):
        all_files[str(resource["id"])] = resource["filename"]
    searched_file_objs = process.extract(
        search_term, all_files, limit=fuzzy_limit)
    all_files = []
    for file in searched_file_objs:
        all_files.append(
            {"id": file[2], "filename": file[0], "search_score": file[1]})
    filenames_payload = {
        'files': all_files,
        'updated_at': datetime.now(),
        'abe_version': VERSION
    }
    if err_msg:
        filenames_payload['err_msg'] = err_msg
    return jsonify(filenames_payload)


@APP.route('/abe/latest_mpk')
def get_latest_mpk():
    """Send latest Master Public Key (mpk) value as JSON,
    by generating python dict payload and convering.
    Attached to '/abe/latest_mpk' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask - JSON)
        Generates flask Response object by converting dict to JSON.

    """
    mpk_payload = {
        'generated_at': MASTER_KEY_UPDATED,
        'updated_at': datetime.now(),
        'mpk': MASTER_PUBLIC_KEY.decode('UTF-8'),
        'abe_version': VERSION
    }
    return jsonify(mpk_payload)


@APP.route('/abe/latest_attributes')
def get_latest_attributes():
    """Send latest Global ABE Attributes (gaa) value as JSON,
    by generating python dict payload and convering.
    Attached to '/abe/latest_attributes' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask - JSON)
        Generates flask Response object by converting dict to JSON.

    """
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
