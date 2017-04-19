import os
import sys
import json
import random
import shutil
import yaml

from datetime import datetime
from celery import Celery
from werkzeug.utils import secure_filename
from flask import Flask, request, send_from_directory, redirect

from system_endpoints import system_endpoints
from program_endpoints import program_endpoints
from run_endpoints import run_endpoints
from communication_endpoints import communication_endpoints
from data_model import db, Run, Program, System
from web_utils import error, is_hex

sys.path.append(os.path.join('..', 'vmfuzz'))
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
        req_file = request.files['file']
        if not req_file or req_file.filename == '':
            return '<pre>Error: no file found</pre>'

        fname = secure_filename(req_file.filename)
        corpus_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, 'corpora')
        fpath = os.path.join(corpus_dir, fname)
        req_file.save(fpath)
        return redirect('/')
    return send_from_directory('pub', 'corpora.html')

'''
TASKS AND TASK ENDPOINTS
'''

# Launch !exploitable on the crash_dir on a previous run
# Create a temporary run sent to celery, but do not save this run.
@app.route('/run_exploitable/<run_id>', methods=['POST'])
def run_exploitable(run_id):
    """
    Runs !exploitable on all crashes associated with a run
    Args:
        run_id (str): run object id
    Returns:
        json: run_id
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    print "Run !exploitable on id:"+str(run_id)
    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)

    run = runs[0].to_mongo().to_dict()
    run['_id'] = str(run['_id'])
    run['program'] = str(run['program'])

    # TODO: verify end time and status

    progs = Program.objects(id=run['program'])
    prog = progs[0].to_mongo().to_dict()

    prog['_id'] = str(prog['_id'])
    prog['system'] = str(prog['system'])

    syss = System.objects(id=prog['system'])
    system = syss[0].to_mongo().to_dict()

    system['_id'] = str(system['_id'])

    system['webapp_ip'] = WEB_CONFIG['WEBAPP_IP']

    run['run_type'] = 'exploitable'

    task = task_run_start.apply_async(args=[system, prog, run])

    return json.dumps({'run_id': run['_id']})

@app.route('/run_start/<run_id>', methods=['POST'])
def run_start(run_id):
    """
    Executes a run on workers
    Args:
        run_id (str): run object id
    Returns:
        json: run object id
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    print "Run id:"+str(run_id)
    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)

    if runs[0].start_time != None:
        return error('Cannot start run as it has already started!')

    run = runs[0].to_mongo().to_dict()
    run['_id'] = str(run['_id'])
    run['program'] = str(run['program'])

    progs = Program.objects(id=run['program'])
    prog = progs[0].to_mongo().to_dict()

    input_path = os.path.join(PATH_SHARED_INPUT_CRASHES, run['input_dir'])
    ext = prog['file_format']
    flist = os.listdir(input_path)
    flist = [ea for ea in flist if ea.endswith(ext)]
    if len(flist) < 1:
        return error('Please add files to run ending with extension %s' % ext)

    random.shuffle(flist)
    selected_fname = os.path.join(input_path, flist[0])
    seed_fname = os.path.join(input_path, 'seed%s' % ext)
    if selected_fname != seed_fname:
        shutil.copy2(selected_fname, seed_fname)

    prog['_id'] = str(prog['_id'])
    prog['system'] = str(prog['system'])
    # print prog

    syss = System.objects(id=prog['system'])
    system = syss[0].to_mongo().to_dict()

    system['_id'] = str(system['_id'])

    system['webapp_ip'] = WEB_CONFIG['WEBAPP_IP']

    if 'number_workers' in run:
        number_workers = max(1, run['number_workers'])
    else:
        run['number_workers'] = 1
        number_workers = 1

    print "Number of workers: " + str(number_workers)

    run_to_update = runs[0]

    for worker_id in xrange(number_workers):
        print "launch "+str(worker_id)
        run['_worker_id'] = worker_id
        task = task_run_start.apply_async(args=[system, prog, run])
        run_to_update.workers.append('STARTING')
        run_to_update.errors.append('')
        run_to_update.stats.append([])

    run_to_update.status = 'STARTING'
    run_to_update.start_time = datetime.now()
    run_to_update.save()
    # print task.id
    return json.dumps({'run_id': run['_id']})

@celery.task
def task_run_start(system, program, run):
    """
    Executes vmfuzz on a set of configs
    Args:
         system (dict): system config
         program (dict): program config
         run (dict): run confg
    """
    vmfuzz.fuzz(system, program, run)

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
