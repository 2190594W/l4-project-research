import os, sys, pyopenabe
from datetime import datetime
from flask import Flask, flash, session, request, redirect, render_template,\
url_for, send_from_directory, jsonify
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/tmp/flask/file/uploads'
ALLOWED_EXTENSIONS = set(['cpabe', 'jp2'])

VERSION = 'v0.0.1'

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

app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
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
@app.route('/get_filenames')
def get_filenames():
    all_files = []
    for root, dirs, files in os.walk(app.config['UPLOAD_FOLDER']):
        all_files.extend(files)
    filenames_payload = {
        'files': all_files,
        'updated_at': datetime.now(),
        'abe_version': VERSION
    }
    return jsonify(filenames_payload)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
