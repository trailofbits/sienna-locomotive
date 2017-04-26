import os
import shutil
import json
import time
import yaml

from datetime import datetime
from mongoengine.queryset import NotUniqueError
from mongoengine.queryset import DoesNotExist
from bson import json_util
from flask import Blueprint
from flask import request
from flask import send_from_directory
from werkzeug.utils import secure_filename


from data_model import Run, Program, System
from web_utils import *

run_endpoints = Blueprint('run_endpoints', __name__)

with open('config.yaml') as config_file:
    contents = config_file.read()
    WEB_CONFIG = yaml.load(contents)

# input_crashes from the web app's view
PATH_SHARED_INPUT_CRASHES = WEB_CONFIG['PATH_SHARED']

@run_endpoints.route('/run_crash_download/<run_id>/<crash_name>')
def docs(run_id, crash_name):
    """
    Download a crash.
    Args:
        run_id (str): description
        crash_name (str): description
    Returns:
        file: contents of index.html
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    run = Run.objects(id=run_id)
    if len(run) != 1:
        return error('Run with id not found: %s' % run_id)

    crash_path = os.path.join(PATH_SHARED_INPUT_CRASHES, run[0].crash_dir)
    flist = os.listdir(crash_path)

    if crash_name not in flist:
        return error('Crash not found with name: %s' % crash_name)

    return send_from_directory(crash_path, crash_name)

@run_endpoints.route('/run_add', methods=['POST'])
def run_add():
    """
    Add a run config
    Args:
        name (str): name of the run
    Returns:
        json: object id of the created run config
    """
    config_str = request.form['yaml']
    try:
        config = yaml.load(config_str)
    except yaml.scanner.ScannerError, e:
        return error('YAML load failed with message: \n' + str(e))

    if 'name' not in config:
        config['name'] = 'run_%s' % hex(int(time.time()))[2:]

    missing = []
    for key in Run.user_all:
        if key not in config:
            missing.append(key)

    if len(missing) != 0:
        return error('Missing required fields: %s' % ' '.join(missing))

    if config['run_type'] not in ['all', 'exploitable']:
        return error('Unsupported run type: %s' % ' '.join(config['run_type']))

    # get system path_input_crashes
    program_id = config['program']
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    prog = Program.objects(id=program_id)
    if len(prog) != 1:
        return error('Program id invalid: %s' % config['program'])

    # create input dir
    input_dir = 'input_%s' % hex(int(time.time()))[2:]
    # create output dir
    crash_dir = 'crash_%s' % hex(int(time.time()))[2:]

    web_input_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, input_dir)
    web_crash_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, crash_dir)

    mkdir_ifne(web_input_dir)
    mkdir_ifne(web_crash_dir)

    if 'input_dir' not in config:
        config['input_dir'] = input_dir

    if 'crash_dir' not in config:
        config['crash_dir'] = crash_dir

    if 'number_workers' not in config:
        config['number_workers'] = 1

    if 'hours' in config and 'mins' in config:
        timeout = config['mins'] + config['hours'] * 60
        if timeout > 0:
            config['fuzz_time'] = timeout
        config.pop('hours')
        config.pop('mins')

    # for key in config:
        # if key not in Run.required_all:
            # config.pop(key, None)

    try:
        print config
        run = Run(**config)
        run.save()

        prog = run['program']
    except NotUniqueError:
        return error('Name already in use: %s' % config['name'])

    return json.dumps({'run_id': str(run.id)})

@run_endpoints.route('/run_list/<program_id>')
def run_list(program_id):
    """
    List runs associated with program config
    Args:
        program_id (str): id of the program config
    Returns:
        json: list of runs
    """
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    print "Program id " + str(program_id)
    runs = [run.to_mongo().to_dict() for run in Run.objects(program=program_id)]
    for run in runs:
        run['_id'] = str(run['_id'])
        run['program'] = str(run['program'])

        if 'start_time' in run:
            run['start_time'] = time.mktime(run['start_time'].timetuple())

        if 'end_time' in run:
            run['end_time'] = time.mktime(run['end_time'].timetuple())

    print "Run id "+str(runs[0]['_id'])

    run_info = {'order': Run.required, 'runs': runs}
    return json.dumps(run_info, default=json_util.default)

@run_endpoints.route('/run_list_crashes/<run_id>')
def run_list_crashes(run_id):
    """
    List crashes belonging to a run
    Args:
        run_id (str): object id of the run
    Returns:
        json: list of files associated with run
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    run = Run.objects(id=run_id)
    if len(run) != 1:
        return error('Run with id not found: %s' % run_id)

    crash_path = os.path.join(PATH_SHARED_INPUT_CRASHES, run[0].crash_dir)
    flist = os.listdir(crash_path)

    crashes = sorted([ea for ea in flist if '-C.' in ea])
    hangs = sorted([ea for ea in flist if '-H.' in ea])

    classifications = {}
    if 'crash_classifications' in run[0]:
        classifications = run[0]['crash_classifications']

    return json.dumps({'crashes': crashes+hangs, 'classifications': classifications})

# upload seed file
@run_endpoints.route('/run_files_add', methods=['POST'])
def run_files_add():
    """
    Associate files from the corpus with a run
    Args:
        run_id (str): object id of the run
        files (list of str): list of files to be added
    Returns:
        json: list of files associated with run
    """
    # copy file to input directory
    run_id = request.json['run_id']

    # print request.json['files']
    fnames = [secure_filename(fname) for fname in request.json['files']]

    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    run = Run.objects(id=run_id)
    if len(run) != 1:
        return error('Run with id not found: %s' % run_id)

    input_path = os.path.join(PATH_SHARED_INPUT_CRASHES, run[0].input_dir)

    not_found = []
    for fname in fnames:
        corpus_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, 'corpora')
        corpus_file = os.path.join(corpus_dir, fname)

        if not os.path.exists(corpus_file):
            not_found.append(fname)
            continue

        shutil.copy2(corpus_file, input_path)

    if len(not_found) > 0:
        return error('File not found: %s' % ', '.join(fname))

    flist = os.listdir(input_path)

    return json.dumps(flist)

# upload seed file
@run_endpoints.route('/run_files_remove', methods=['POST'])
def run_files_remove():
    """
    Remove file from run
    Args:
        run_id (str): object if of the run
        files (list of str): list of files to be removed
    Returns:
        json: list of files associated with run
    """
    # copy file to input directory
    run_id = request.json['run_id']
    # print request.json['files']
    fnames = [secure_filename(fname) for fname in request.json['files']]

    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    run = Run.objects(id=run_id)
    if len(run) != 1:
        return error('Run with id not found: %s' % run_id)

    input_path = os.path.join(PATH_SHARED_INPUT_CRASHES, run[0].input_dir)

    not_found = []
    for fname in fnames:
        input_file = os.path.join(input_path, fname)

        if not os.path.exists(input_file):
            not_found.append(fname)
            continue

        os.remove(input_file)

    if len(not_found) > 0:
        return error('File not found: %s' % ', '.join(fname))

    flist = os.listdir(input_path)

    return json.dumps(flist)

# Add all files in the corpora dir that end with the targeted extension
# run_default_corpus
@run_endpoints.route('/run_files_all_add/<run_id>', methods=['POST'])
def run_default_corpus(run_id):
    """
    Adds all files to the run, from the corpus, with matching extension
    Args:
        run_id (str): run object id
    Returns:
        json: list of files associated with run
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    run = Run.objects(id=run_id)[0]
    prog = run['program']

    corpus_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, 'corpora')
    fnames = [secure_filename(f) for f in os.listdir(corpus_dir)]
    fnames = [f for f in fnames if os.path.isfile(os.path.join(corpus_dir, f))]
    fnames = [f for f  in fnames if f.endswith(prog['file_format'])]

    input_path = os.path.join(PATH_SHARED_INPUT_CRASHES, run[0].input_dir)

    for fname in fnames:
        corpus_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, 'corpora')
        corpus_file = os.path.join(corpus_dir, fname)

        shutil.copy2(corpus_file, input_path)

    flist = os.listdir(input_path)

    return json.dumps(flist)

@run_endpoints.route('/run_files_list/<run_id>')
def run_files_list(run_id):
    """
    Lists files associated with run
    Args:
        run_id (str): run object id
    Returns:
        json: list of files associated with run
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    run = Run.objects(id=run_id)
    if len(run) != 1:
        return error('Run with id not found: %s' % run_id)

    input_path = os.path.join(PATH_SHARED_INPUT_CRASHES, run[0].input_dir)
    flist = os.listdir(input_path)

    return json.dumps(flist)

@run_endpoints.route('/run_stop/<run_id>', methods=['POST'])
def run_stop(run_id):
    """
    Stops a run
    Args:
        run_id (str): run object id
    Returns:
        json: run object id
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)

    if runs[0].end_time != None:
        return error('Cannot stop run as it has already stopped!')

    run_to_update = runs[0]
    run_to_update['status'] = 'STOPPING'
    run_to_update.end_time = datetime.now()
    run_to_update.save()

    print dir(run_to_update)

    return json.dumps({'run_id': str(run_to_update['id'])})

@run_endpoints.route('/run_edit', methods=['POST'])
def run_edit():
    """
    Edit a run
    Args:
        run_id (str): run object id
    Returns:
        json: success message
    """
    run_id = request.form['run_id']

    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    run = Run.objects(id=run_id)
    if len(run) != 1:
        return error('Run with id not found: %s' % run_id)

    if run[0].start_time != None:
        return error('Cannot edit a run once it has started!')

    config_str = request.form['yaml']
    try:
        config = yaml.load(config_str)
    except yaml.scanner.ScannerError, e:
        return error('YAML load failed with message: \n' + str(e))

    # TODO: check config against allowed variables
    invalid = ['input_dir', 'crash_dir', 'start_time', 'end_time', 'number_workers', 'run_type']
    for key in invalid:
        if key in config and key in run:
            config[key] = run[key]
        elif key in config:
            config.pop(key)

    run[0].modify(**config)
    return json.dumps({'success': True, 'message': 'Successfully edited %s' % run_id})

@run_endpoints.route('/run_delete/<run_id>', methods=['POST'])
def run_delete(run_id):
    """
    Delete a run
    Args:
        run_id (str): run object id
    Returns:
        json: success message
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)

    if runs[0].start_time != None and runs[0].end_time is None:
        return error('Cannot delete a run while it is running!')

    run_to_remove = runs[0]
    run_to_remove.delete()

    # TODO: delete directories?

    # print task.id
    return json.dumps({'success': True, 'message': 'Successfully deleted %s' % run_id})

@run_endpoints.route('/run_active_list')
def run_active_list():
    """
    List active runs
    Returns:
        json: list of active runs
    """
    runs = Run.objects.filter(start_time__ne='', status='RUNNING')
    min_runs = []
    for run in runs:
        min_run = {}
        min_run['system'] = str(run['program']['system'].id)
        min_run['program'] = str(run['program'].id)

        run = run.to_mongo().to_dict()
        min_run['name'] = run['name']
        min_run['_id'] = str(run['_id'])
        min_run['status'] = run['status']

        if 'start_time' in run:
            min_run['start_time'] = time.mktime(run['start_time'].timetuple())

        if 'end_time' in run:
            continue

        min_runs.append(min_run)

    run_info = {'runs': min_runs}
    return json.dumps(run_info, default=json_util.default)

@run_endpoints.route('/run_complete_list')
def run_complete_list():
    """
    List completed runs
    Returns:
        json: list of completed runs
    """
    runs = Run.objects(start_time__ne='', status__in=['FINISHED', 'ERROR', 'TRIAGE'])
    min_runs = []
    for run in runs:
        try:
            min_run = {}
            min_run['system'] = str(run['program']['system'].id)
            min_run['program'] = str(run['program'].id)

            run = run.to_mongo().to_dict()
            min_run['name'] = run['name']
            min_run['_id'] = str(run['_id'])
            min_run['status'] = run['status']

            if 'start_time' in run:
                min_run['start_time'] = time.mktime(run['start_time'].timetuple())

            if 'end_time' in run:
                min_run['end_time'] = time.mktime(run['end_time'].timetuple())

            min_runs.append(min_run)
        except DoesNotExist as e:
            pass
            

    run_info = {'runs': min_runs}
    return json.dumps(run_info, default=json_util.default)

@run_endpoints.route('/run_status_workers/<run_id>', methods=['GET'])
def run_status_workers(run_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    run = runs[0]
    return json.dumps(run.workers)

@run_endpoints.route('/run_stats_worker/<run_id>/<worker_id>', methods=['GET'])
def run_stats_worker(run_id, worker_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('Run not found with id: %s' % run_id)

    run = runs[0]
    if worker_id.isdigit():
        worker_id = int(worker_id)
    else:
        worker_id = 0

    if worker_id < run.number_workers and worker_id >= 0:
        return json.dumps(run.stats[worker_id])
    else:
        return error("Invalid worker_id")

@run_endpoints.route('/run_stats_all/<run_id>', methods=['GET'])
def run_stats_all(run_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    run = runs[0]
    stats = []
    for stat in run.stats:
        stats.append(stat)
    return json.dumps({'stats': stats, 'status': run.workers})
