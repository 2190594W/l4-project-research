"""
Master Key Server module
"""

from io import BytesIO
from sys import exc_info
from os import urandom, path
from datetime import datetime
from functools import partial
from flask import Flask, request, send_file, render_template, jsonify, abort
from flask.logging import create_logger
#pylint: disable=E0401
import jsonpickle
import pyopenabe

VERSION = 'v0.0.2'

MASTER_SECRET_KEY_FILE = 'master_secret_key.key'
MASTER_PUBLIC_KEY_FILE = 'master_public_key.key'

GLOBAL_ABE_ATTRS_FILE = 'global_attrs.config'

APP = Flask(__name__)
LOG = create_logger(APP)

try:
    with open('session_secret.config', 'rb') as session_secret:
        APP.secret_key = session_secret.read().strip()
        if len(APP.secret_key) > 32:
            LOG.info("Configured session secret")
        else:
            raise ValueError("Insufficient session secret provided")
except EnvironmentError:
    LOG.error("No sufficient session secret found, auto-generated random 64-bytes.")
    APP.secret_key = urandom(64)

OPENABE = pyopenabe.PyOpenABE()
CPABE = OPENABE.CreateABEContext("CP-ABE")

try:
    with open(MASTER_SECRET_KEY_FILE, 'rb') as mskf:
        MASTER_SECRET_KEY = mskf.read()
    with open(MASTER_PUBLIC_KEY_FILE, 'rb') as mpkf:
        MASTER_PUBLIC_KEY = mpkf.read()
    CPABE.importSecretParams(MASTER_SECRET_KEY)
    CPABE.importPublicParams(MASTER_PUBLIC_KEY)
    MASTER_KEYS_GENERATED = datetime.fromtimestamp(path.getmtime(MASTER_SECRET_KEY_FILE))
except EnvironmentError:
    try:
        CPABE.generateParams()
        MASTER_SECRET_KEY = CPABE.exportSecretParams()
        MASTER_PUBLIC_KEY = CPABE.exportPublicParams()
        with open(MASTER_SECRET_KEY_FILE, 'wb') as mskf:
            mskf.write(MASTER_SECRET_KEY)
        with open(MASTER_PUBLIC_KEY_FILE, 'wb') as mpkf:
            mpkf.write(MASTER_PUBLIC_KEY)
        MASTER_KEYS_GENERATED = datetime.now()
    except EnvironmentError:
        LOG.error("FATAL ERROR: ABORTING SERVER")
        LOG.error("Unexpected error: %s", exc_info()[0])
        exit()

try:
    with open(GLOBAL_ABE_ATTRS_FILE, 'r') as gaaf:
        GLOBAL_ABE_ATTRS_JSON_PICKLED = gaaf.read()
    GLOBAL_ABE_ATTRS = jsonpickle.decode(GLOBAL_ABE_ATTRS_JSON_PICKLED)
    GLOBAL_ABE_ATTRS_GENERATED = datetime.fromtimestamp(path.getmtime(GLOBAL_ABE_ATTRS_FILE))
except EnvironmentError:
    LOG.error("Unable to recover global attributes file. Generating blank template...")
    GLOBAL_ABE_ATTRS = {'strings': set(), 'integers': set(), 'dates': set(),\
        'arrays': set(), 'flags': set()}
    GLOBAL_ABE_ATTRS_JSON_PICKLED = jsonpickle.encode(GLOBAL_ABE_ATTRS)
    GLOBAL_ABE_ATTRS_GENERATED = datetime.now()

del CPABE, OPENABE

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

@APP.route('/abe/get_public_key')
def get_public_key():
    """Send latest Master Public Key (mpk) value as JSON,
    by generating python dict payload and convering.
    Attached to '/abe/get_public_key' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask - JSON)
        Generates flask Response object by converting dict to JSON.

    """
    mpk_payload = {
        'generated_at': MASTER_KEYS_GENERATED,
        'updated_at': datetime.now(),
        'mpk': MASTER_PUBLIC_KEY.decode('UTF-8'),
        'abe_version': VERSION
    }
    return jsonify(mpk_payload)

@APP.route('/abe/get_attributes')
def get_attributes():
    """Send latest Global ABE Attributes (gaa) value as JSON,
    by generating python dict payload and convering.
    Attached to '/abe/get_attributes' route by flask annotation.

    Parameters
    ----------


    Returns
    -------
    Response (flask - JSON)
        Generates flask Response object by converting dict to JSON.

    """
    new_attrs = GLOBAL_ABE_ATTRS
    for attr in new_attrs:
        new_attrs[attr] = list(new_attrs[attr])
    attributes_payload = {
        'generated_at': GLOBAL_ABE_ATTRS_GENERATED,
        'updated_at': datetime.now(),
        'attributes': new_attrs,
        'abe_version': VERSION
    }
    return jsonify(attributes_payload)

def assign_value_key(attr_type, key, value):
    """Small function to provide the correct PyOpenABE separator
    for an attribute, based on its type.

    Parameters
    ----------
    attr_type : string
        String for `attr_type` describing the type of the attribute.
    key : string
        String for the `key` of the attribute.
    value : string
        String representing the `value` of the attribute.

    Returns
    -------
    string
        Reformatted string equivalent of the attribute.

    """
    attr_separators = {"strings": ":", "integers": "=", "dates": " = ", "arrays": ":"}
    separator = attr_separators[attr_type]
    value = f"|{key}{separator}".join(map(str, value)) if attr_type == "arrays" else value
    return f"{key}{separator}{value}"

def create_attr_list(attrs):
    """Create string 'list' of user attributes from a dictionary.
    The returned string is just the PyOpenABE format for `attrs`.

    Parameters
    ----------
    attrs : dict
        Dictionary of `attrs` that are to be issued for a user key generation.

    Returns
    -------
    string
        String representing the `attrs` as an PyOpenABE compatible string.

    """
    user_attr_list = "|"
    for attr_type, attr in attrs.items():
        if attr_type in ('strings', 'integers', 'dates', 'arrays'):
            formatted_attrs = list(map(partial(assign_value_key, attr_type),\
                attr.keys(), attr.values()))
            user_attr_list += "|".join(formatted_attrs) + "|"
        elif attr_type == 'flags':
            user_attr_list += "|".join(attr) + "|"
        else:
            pass
    return user_attr_list

def update_global_attrs(attrs):
    """Given a dictionary of recently issued attributes, updates
    the global list of attributes with any new attributes.

    Parameters
    ----------
    attrs : dict
        Dictionary of `attrs` that have just been issued during a user
        key generation.

    Returns
    -------

    """
    #pylint: disable=W0603
    global GLOBAL_ABE_ATTRS_JSON_PICKLED, GLOBAL_ABE_ATTRS_GENERATED
    for attr_type, attr in attrs.items():
        if attr_type in ('strings', 'integers', 'dates', 'arrays', 'flags'):
            for key in attr:
                GLOBAL_ABE_ATTRS[attr_type].add(key)
    if GLOBAL_ABE_ATTRS_JSON_PICKLED != jsonpickle.encode(GLOBAL_ABE_ATTRS):
        GLOBAL_ABE_ATTRS_JSON_PICKLED = jsonpickle.encode(GLOBAL_ABE_ATTRS)
        with open(GLOBAL_ABE_ATTRS_FILE, 'w') as gaa_f:
            gaa_f.write(GLOBAL_ABE_ATTRS_JSON_PICKLED)
        GLOBAL_ABE_ATTRS_GENERATED = datetime.now()


@APP.route('/abe/generate_userkey/<string:file_or_json>', methods=['POST'])
def generate_userkey(file_or_json):
    """Route for generating a new User Key.
    Can either return the new Key as part of a JSON payload or as
    a File attachment. Requires POST method, since the user's attributes
    must be provided for generation.
    Attached to '/abe/generate_userkey/<string:file_or_json>' route by flask annotation.

    Parameters
    ----------
    file_or_json : string
        String flag representing if the returned value should be a
        BytesIO file or JSON string, `file_or_json`.

    Returns
    -------
    Response (flask)
        Generates flask Response object from a generated BytesIO file.

    """
    if file_or_json not in ("file", "json"):
        abort(404)
    openabe_inst = pyopenabe.PyOpenABE()
    cpabe = openabe_inst.CreateABEContext("CP-ABE")
    cpabe.importSecretParams(MASTER_SECRET_KEY)
    cpabe.importPublicParams(MASTER_PUBLIC_KEY)
    user_attrs = request.get_json()
    if user_attrs is not None:
        if all(key in user_attrs for key in ('attributes', 'username')):
            str_username = str(user_attrs['username'])
            attrs = user_attrs['attributes']
            update_global_attrs(attrs)
            user_attr_list = create_attr_list(attrs)
            del user_attrs
            try:
                cpabe.keygen(user_attr_list, str_username)
                LOG.info("successfully generated key")
                userkey_generated_at = datetime.now()
                userkey = cpabe.exportUserKey(str_username)
            except pyopenabe.PyOpenABEError as err:
                LOG.error("Fatal error during key generation: %s", err)
                return jsonify({'msg': 'FATAL ERROR'}), 500

            if file_or_json == "json":
                userkey_payload = {
                    'filename': f"{str_username}.key",
                    'generated_at': userkey_generated_at,
                    'updated_at': datetime.now(),
                    'userkey': userkey.decode('UTF-8'),
                    'user_attrs': user_attr_list,
                    'abe_version': VERSION
                }
                return jsonify(userkey_payload)
            return send_file(
                BytesIO(userkey),
                mimetype='text/plain',
                as_attachment=True,
                attachment_filename=f"{str_username}.key")
    return jsonify({'msg': 'Improper JSON values. Ensure both "attributes" and\
        "username" keys are present!'}), 422

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
        LOG.error("404 Error occurred: %s", error)
    return render_template('404.html', error=template_error), 404
