from flask import Flask, request, send_from_directory, redirect
from werkzeug.utils import secure_filename

from celery import Celery

import json
import yaml
import sys
import os

from system_endpoints import system_endpoints
from program_endpoints import program_endpoints
from run_endpoints import run_endpoints
from communication_endpoints import communication_endpoints
from data_model import *
from web_utils import *

sys.path.append(os.path.join('..','vmfuzz'))
import vmfuzz

'''
INITIALIZATION
'''

with open('config.yaml') as f:
    contents = f.read()
    WEB_CONFIG = yaml.load(contents)

# input_crashes from the web app's view
PATH_SHARED_INPUT_CRASHES = WEB_CONFIG['PATH_SHARED']

app = Flask('web')

app.config['MONGODB_SETTINGS'] = {
    'db': 'fuzzdb',
    'host': WEB_CONFIG['MONGO_IP'],
    'port': 27017
}

app.config['CELERY_BROKER_URL'] = 'redis://'+WEB_CONFIG['REDIS_IP']+':6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://'+WEB_CONFIG['REDIS_IP']+':6379/0'
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

app.register_blueprint(system_endpoints)
app.register_blueprint(program_endpoints)
app.register_blueprint(run_endpoints)
app.register_blueprint(communication_endpoints)

db.init_app(app)

'''
WEB ENDPOINTS
'''

# MISC

@app.route('/')
def root():
    """
    Web root, index.html
    Args:
        arg (type): description
    Returns:
        file: contents of index.html
    """
    return send_from_directory('pub', 'index.html')

@app.route('/docs')
def docs():
    """
    Web root, index.html
    Args:
        arg (type): description
    Returns:
        file: contents of index.html
    """
    return send_from_directory('pub', 'docs.html')

# TODO: Integrate this into index.html
@app.route('/client')
def client():
    return send_from_directory('pub', 'client.html')

@app.route('/js/<path:path>')
def send_js(path):
    """
    Sends Javascript files from pub/js/
    Args:
        path (str): path to JS file in pub/js/
    Returns:
        file: JS file, if found
    """
    return send_from_directory('pub/js', path)

@app.route('/css/<path:path>')
def send_css(path):
    """
    Sends CSS files from pub/css/
    Args:
        path (str): path to CSS file in pub/css/
    Returns:
        file: CSS file, if found
    """
    return send_from_directory('pub/css', path)

# CORPORA

@app.route('/corpus_files_list')
def corpus_files_list():
    """
    List files in corpus
    Returns:
        json: list of files
    """
    corpus_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, 'corpora')
    flist = os.listdir(corpus_dir)
    return json.dumps(flist)

@app.route('/corpora', methods=['GET', 'POST'])
def corpora():
    """
    Corpus upload page. GET displays page.
    POST uploads a file.
    Args:
        file (file): uploaded file
    Returns:
        page: upload page or webroot
    """
    if request.method == 'POST':
        if 'file' not in request.files:
            return '<pre>Error: no file found</pre>'
        file = request.files['file']
        if not file or file.filename == '':
            return '<pre>Error: no file found</pre>'

        fname = secure_filename(file.filename)
        corpus_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, 'corpora')
        fpath = os.path.join(corpus_dir, fname)
        file.save(fpath)
        return redirect('/')
    return send_from_directory('pub', 'corpora.html')

'''
TASKS
'''

@celery.task
def task_run_start(sys, prog, run):
    """
    Executes vmfuzz on a set of configs
    Args:
         sys (dict): system config
         prog (dict): program config
         run (dict): run confg
    """
    vmfuzz.fuzz(sys, prog, run)

'''
MAIN
'''
if __name__ == '__main__':
    app.run(debug=True, host=WEB_CONFIG['WEBAPP_IP'])



    """
    Description
    Args:
        arg (type): description
    Returns:
        type: description
    """