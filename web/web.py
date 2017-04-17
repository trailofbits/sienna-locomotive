from flask import Flask, request, g, escape, send_from_directory, redirect
from mongoengine.queryset import NotUniqueError
from flask_mongoengine import MongoEngine

from werkzeug.utils import secure_filename

from celery.result import AsyncResult
from celery import Celery, signals

from datetime import datetime

import random
import shutil
import json
import time
import yaml
import sys
import os
import re

from bson.objectid import ObjectId
from bson import json_util


sys.path.append(os.path.join('..','vmfuzz'))
import vmfuzz

'''
INITIALIZATION
'''

with open('config.yaml') as f:
    contents = f.read()
    WEB_CONFIG = yaml.load(contents)

app = Flask('web')

app.config['MONGODB_SETTINGS'] = {
    'db': 'fuzzdb',
    'host': WEB_CONFIG['MONGO_IP'],
    'port': 27017
}
db = MongoEngine(app)

app.config['CELERY_BROKER_URL'] = 'redis://'+WEB_CONFIG['REDIS_IP']+':6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://'+WEB_CONFIG['REDIS_IP']+':6379/0'
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# input_crashes from the web app's view
PATH_SHARED_INPUT_CRASHES = WEB_CONFIG['PATH_SHARED']


'''
DATA MODEL
'''

# system object
class System(db.Document):
    required = [
        'name',
        'path_vmfuzz', 
        'path_input_crashes',
        'path_winafl', 
        'path_dynamorio', 
        'path_windbg', 
        'path_radamsa', 
        'path_autoit', 
        'path_winafl_working_dir', 
        'path_autoit_working_dir', 
        'path_radamsa_working_dir',
        'fuzzers']

    name = db.StringField(unique=True)
    path_vmfuzz = db.StringField()
    path_input_crashes = db.StringField()
    path_winafl = db.StringField()
    path_dynamorio = db.StringField()
    path_windbg = db.StringField()
    path_autoit = db.StringField()
    path_radamsa = db.StringField()
    path_winafl_working_dir = db.StringField()
    path_autoit_working_dir = db.StringField()
    path_radamsa_working_dir = db.StringField()
    fuzzers = db.ListField(db.StringField())


# vmfuzz parent class
class Program(db.Document):
    meta = {'allow_inheritance': True}

    required = [
            'name',
            'arch',
            'using_autoit',
            'path_program',
            'program_name',
            'file_format',
            'system']    

    # Required
    name = db.StringField(unique=True)
    arch = db.StringField()
    using_autoit = db.BooleanField()
    path_program = db.StringField()
    program_name = db.StringField()
    seed_pattern = db.StringField()
    file_format = db.StringField()
    system = db.ReferenceField(System)

    targets = db.ListField(db.DictField())
    crashes_classified = db.ListField(db.DictField())

class ProgramAutoIT(Program):
    required = [
            'name',
            'arch',
            'using_autoit', # true
            'path_program',
            'program_name',
            'file_format',
            'system',
            'path_autoit_script']

    # With Autoit
    path_autoit_script = db.StringField()

class ProgramCMD(Program):
    required = [
            'name',
            'arch',
            'using_autoit', # false
            'path_program',
            'program_name',
            'file_format',
            'system',
            'auto_close',
            'running_time',
            'parameters',]

    # Without Autoit
    auto_close = db.BooleanField()
    running_time = db.IntField()
    parameters = db.ListField(db.StringField())



class Run(db.Document):
    required = [
            'name',
            'input_dir',
            'crash_dir',
            'winafl_targets',
            'fuzz_time',
            'run_type',
            'radamsa_number_files_to_create',
            'winafl_default_timeout',
            'winafl_last_path_timeout',
            'winafl_fuzzing_iteration',
            'start_time',
            'end_time',
            'program']

    user_all = [
            'name',
            'run_type',
            'program']

    required_all = [
            'name',
            'run_type',
            'input_dir',
            'crash_dir',
            'program']

    # all
    name = db.StringField(unique=True)
    run_type = db.StringField()
    program = db.ReferenceField(Program)
    fuzz_time = db.IntField()
    # webapp
    input_dir = db.StringField()
    crash_dir = db.StringField()
    start_time = db.DateTimeField()
    end_time = db.DateTimeField()
    # radamsa
    radamsa_number_files_to_create = db.IntField()
    # winafl
    winafl_targets = db.DictField()
    winafl_default_timeout = db.IntField()
    winafl_last_path_timeout = db.IntField()
    winafl_fuzzing_iteration = db.IntField()
    # book keeping
    status = db.StringField()
    workers = db.ListField(db.StringField())
    number_workers = db.IntField()
    # stats
    stats = db.ListField(db.ListField(db.DictField()))


'''
WEB ENDPOINTS
'''

# MISC

def error(msg):
    """
    Wrap a string in a JSON error for the front end
    Args:
        msg (str): error message
    Returns:
        str: stringified JSON error message
    """
    return json.dumps({'error': True, 'message': msg})

def mkdir_ifne(path):
    """
    Creates a directory if it does not exist
    Args:
        path (str): path of dir to be created
    """
    if not os.path.exists(path):
        print "Make dir "+str(path)
        os.mkdir(path)

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

def is_hex(target):
    return all(ch in 'ABCDEFabcdef0123456789' for ch in target)

# SYSTEM

@app.route('/sys_add', methods=['POST'])
def sys_add():
    """
    Adds a system config
    Args:
        yaml (str): config in yaml format
    Returns:
        json: id of the created system
    """
    config_str = request.form['yaml']
    config = yaml.load(config_str)
    # print config

    missing = []
    for key in System.required:
        if key not in config:
            missing.append(key)    

    if len(missing) != 0:
        return error('Missing required fields: %s' % ' '.join(missing))

#    for key in config:
#        if key not in System.required:
#            config.pop(key, None)

    try:
        sys = System(**config)
        sys.save()
    except NotUniqueError:
        return error('Name already in use: %s' % config['name'])

    return json.dumps({'system_id': str(sys.id)})

@app.route('/sys_list')
def sys_list():
    """
    List available system configs
    Returns:
        json: list of systems
    """
    objs = System.objects()
    if len(objs) < 1:
        return json.dumps([])

    systems = [sys.to_mongo().to_dict() for sys in objs]
    # print systems
    for sys in systems:
        sys['_id'] = str(sys['_id'])

    systems_info = {'order': System.required, 'systems': systems}
    return json.dumps(systems_info)

@app.route('/sys_delete', methods=['POST'])
def sys_delete():
    """
    Deletes a system config
    Args:
        system_id (str): database id of the system object
    Returns:
        json: success message
    """
    
    # TODO: Delete all programs, runs associated

    system_id = request.form['system_id']
    if len(system_id) not in [12, 24] or not is_hex(system_id):
        return error('System id invalid: %s' % system_id)

    system = System.objects(id=system_id)
    if len(system) != 1:
        return error('System id invalid: %s' % system_id)
    system[0].delete()
    return json.dumps({'success': True, 'message': 'Successfully deleted %s' % system_id})

@app.route('/sys_edit', methods=['POST'])
def sys_edit():
    """
    Edit a system config
    Args:
        system_id (str): database id of the system object
        yaml (str): updated yaml config for the system
    Returns:
        json: success message
    """
    system_id = request.form['system_id']
    if len(system_id) not in [12, 24] or not is_hex(system_id):
        return error('System id invalid: %s' % system_id)

    system = System.objects(id=system_id)
    if len(system) != 1:
        return error('System with id not found: %s' % system_id)

    config_str = request.form['yaml']
    config = yaml.load(config_str)

    system[0].modify(**config)
    return json.dumps({'success': True, 'message': 'Successfully edited %s' % system_id})

# PROGRAM

@app.route('/prog_add_gui', methods=['POST'])
def prog_add_gui():
    """
    Adds a program (GUI) config
    Args:
        yaml (str): yaml config of the program object
    Returns:
        json: id of the created program
    """
    config_str = request.form['yaml']
    config = yaml.load(config_str)
    # print config

    missing = []
    for key in ProgramAutoIT.required:
        if key not in config:
            missing.append(key)    

    if len(missing) != 0:
        return error('Missing required fields: %s' % ' '.join(missing))

#    for key in config:
#        if key not in ProgramAutoIT.required:
#            config.pop(key, None)

    try:
        prog = ProgramAutoIT(**config)
        prog.save()
    except NotUniqueError:
        return error('Name already in use: %s' % config['name'])

    return json.dumps({'program_id': str(prog.id)})

@app.route('/prog_add_cmd', methods=['POST'])
def prog_add_cmd():
    """
    Adds a program (CMD) config
    Args:
        yaml (str): yaml config of the program object
    Returns:
        json: id of the created program
    """
    config_str = request.form['yaml']
    config = yaml.load(config_str)
    # print config

    missing = []
    for key in ProgramCMD.required:
        if key not in config:
            missing.append(key)    

    if len(missing) != 0:
        return error('Missing required fields: %s' % ' '.join(missing))

    system_id = config['system']
    if len(system_id) not in [12, 24] or not is_hex(system_id):
        return error('System id invalid: %s' % system_id)

    system = System.objects(id=system_id)
    if len(system) != 1:
        return error('System with id not found: %s' % system_id)

#    for key in config.item():
#        if key not in ProgramCMD.required:
#            config.pop(key, None)

    try:
        prog = ProgramCMD(**config)
        prog.save()
    except NotUniqueError:
        return error('Name already in use: %s' % config['name'])

    return json.dumps({'program_id': str(prog.id)})

@app.route('/prog_list/<system_id>')
def prog_list(system_id):
    """
    List of program configs per system
    Args:
        system_id (str): id of the system object
    Returns:
        json: list of programs (cmd and gui)
    """
    if len(system_id) not in [12, 24] or not is_hex(system_id):
        return error('System id invalid: %s' % system_id)

    programs_gui = [prog.to_mongo().to_dict() for prog in ProgramAutoIT.objects(system=system_id)]
    # print programs_gui
    for prog in programs_gui:
        prog['_id'] = str(prog['_id'])
        prog['system'] = str(prog['system'])

    programs_cmd = [prog.to_mongo().to_dict() for prog in ProgramCMD.objects(system=system_id)]
    # print programs_cmd
    for prog in programs_cmd:
        prog['_id'] = str(prog['_id'])
        prog['system'] = str(prog['system'])

    program_info = {
        'order_gui': ProgramAutoIT.required, 
        'order_cmd': ProgramCMD.required, 
        # 'programs_gui': programs_gui,
        # 'programs_cmd': programs_cmd,
        'programs': programs_gui + programs_cmd,
    }
    return json.dumps(program_info)

@app.route('/prog_delete', methods=['POST'])
def prog_delete():
    """
    Delete a program config
    Args:
        program_id (str): id of the program object
    Returns:
        json: success message
    """
    # TODO: delete all child runs
    program_id = request.form['program_id']

    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)
    if len(program) != 1:
        return error('Program with id not found: %s' % program_id)
    program[0].delete()
    return json.dumps({'success': True, 'message': 'Successfully deleted %s' % program_id})

@app.route('/prog_edit', methods=['POST'])
def prog_edit():
    program_id = request.form['program_id']

    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)
    if len(program) != 1:
        return error('Program with id not found: %s' % program_id)

    config_str = request.form['yaml']
    config = yaml.load(config_str)

    program[0].modify(**config)
    return json.dumps({'success': True, 'message': 'Successfully edited %s' % program_id})

# RUN

@app.route('/run_add', methods=['POST'])
def run_add():
    """
    Add a run config
    Args:
        name (str): name of the run
    Returns:
        json: object id of the created run config
    """
    config_str = request.form['yaml']
    config = yaml.load(config_str)
    print config
    # print config

    if 'name' not in config:
        config['name'] = 'run_%s' % hex(int(time.time()))[2:]

    missing = []
    for key in Run.user_all:
        if key not in config:
            missing.append(key)    

    if len(missing) != 0:
        return error('Missing required fields: %s' % ' '.join(missing))

    print config['run_type']
    if config['run_type'] not in ['all', 'exploitable']:
        return error('Unsupported run type: %s' % ' '.join(config['run_type']))

    # get system path_input_crashes
    program_id = config['program']
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    prog = Program.objects(id=program_id)
    if len(prog) != 1:
        return error('Program id invalid: %s' % config['program'])
    sys = prog[0]['system']

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
        if timeout>0:
            config['fuzz_time'] = timeout
        config.pop('hours')
        config.pop('mins')
    else:
        print 'no fuzz time'

    print config
#    for key in config:
#        if key not in Run.required_all:
#	    print key
#           config.pop(key, None)

    try:
        print config
        run = Run(**config)
        run.save()
    except NotUniqueError:
        return error('Name already in use: %s' % config['name'])

    return json.dumps({'run_id': str(run.id)})

@app.route('/run_list/<program_id>')
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

	print "Run id "+str(run['_id'])

    run_info = {'order': Run.required, 'runs': runs}
    return json.dumps(run_info, default=json_util.default)

# upload seed file
@app.route('/run_files_add', methods=['POST'])
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
@app.route('/run_files_remove', methods=['POST'])
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
@app.route('/run_files_all_add/<run_id>', methods=['POST'])
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


@app.route('/run_files_list/<run_id>')
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
    sys = syss[0].to_mongo().to_dict()

    sys['_id'] = str(sys['_id'])
    # print sys

    sys['webapp_ip'] = WEB_CONFIG['WEBAPP_IP'] 

    if 'number_workers' in run:
        number_workers = max(1,run['number_workers'])
    else:
        run['number_workers'] = 1
        number_workers = 1

    print "Number of workers: " + str(number_workers)

    run_to_update = runs[0]

    for worker_id in xrange(number_workers):
        run['_worker_id'] = worker_id
        task = task_run_start.apply_async(args=[sys, prog, run])
        run_to_update.workers.append('STARTING')
        run_to_update.stats.append([])

    run_to_update.status = 'STARTING'
    run_to_update.start_time = datetime.now()
    run_to_update.save()
    # print task.id
    return json.dumps({'run_id': run['_id']})

@app.route('/run_stop/<run_id>', methods=['POST'])
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

@app.route('/run_edit', methods=['POST'])
def run_edit():
    run_id = request.form['run_id']

    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    run = Run.objects(id=run_id)
    if len(run) != 1:
        return error('Run with id not found: %s' % run_id)

    if run[0].start_time != None:
        return error('Cannot edit a run once it has started!')

    config_str = request.form['yaml']
    config = yaml.load(config_str)

    # TODO: check config against allowed variables
    run[0].modify(**config)
    return json.dumps({'success': True, 'message': 'Successfully edited %s' % run_id})

@app.route('/run_delete/<run_id>', methods=['POST'])
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

    if runs[0].start_time != None and runs[0].end_time == None:
        return error('Cannot delete a run while it is running!')

    run_to_remove = runs[0] 
    run_to_remove.delete()

    # TODO: delete directories?

    # print task.id
    return json.dumps({'success': True, 'message': 'Successfully deleted %s' % run_id})

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
    sys = syss[0].to_mongo().to_dict()

    sys['_id'] = str(sys['_id'])

    sys['webapp_ip'] = WEB_CONFIG['WEBAPP_IP'] 

    run['run_type'] = 'exploitable'

    task = task_run_start.apply_async(args=[sys, prog, run])
    
    return json.dumps({'run_id': run['_id']})

def run_get_system(run):
    """
    Utility function for getting a run's system
    Args:
        run (object): run database object
    Returns:
        object: system database object
    """
    prog = run['program']
    sys = prog['system']
    return sys

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

# STAT(U)S

@app.route('/run_active_list')
def run_active_list():
    """
    List active runs 
    Returns:
        json: list of active runs
    """
    runs = Run.objects(start_time__ne='', status='RUNNING')
    runs = []
    for run in runs:
        run = run.to_mongo().to_dict()
        min_run = {}
        min_run['name'] = run['name']
        min_run['_id'] = str(run['_id'])
        min_run['system'] = str(run['program']['system'])
        min_run['program'] = str(run['program'])

        if 'start_time' in run:
            min_run['start_time'] = time.mktime(run['start_time'].timetuple())

        if 'end_time' in run:
            continue

        runs.append(min_run)

    run_info = {'runs': runs}
    return json.dumps(run_info, default=json_util.default)

@app.route('/run_complete_list')
def run_complete_list():
    """
    List completed runs 
    Returns:
        json: list of completed runs
    """
    runs = Run.objects(start_time__ne='', end_time__ne='')
    runs = []
    for run in runs:
        run = run.to_mongo().to_dict()
        min_run = {}
        min_run['name'] = run['name']
        min_run['_id'] = str(run['_id'])
        min_run['system'] = str(run['program']['system'])
        min_run['program'] = str(run['program'])

        if 'start_time' in run:
            min_run['start_time'] = time.mktime(run['start_time'].timetuple())

        if 'end_time' in run:
            run['end_time'] = time.mktime(run['end_time'].timetuple())

        runs.append(min_run)

    run_info = {'runs': runs}
    return json.dumps(run_info, default=json_util.default)

@app.route('/run_status_workers/<run_id>', methods=['GET'])
def run_status_workers(run_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    run = runs[0]
    return json.dumps(run.workers)

@app.route('/run_stats_worker/<run_id>/<worker_id>', methods=['GET'])
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

@app.route('/run_stats_all/<run_id>', methods=['GET'])
def run_stats_all(run_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    run = runs[0]
    stats = []
    for s in run.stats:
        stats.append(s)
    return json.dumps({'stats': stats, 'status': run.workers})

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
COMMUNICATION
'''

@app.route('/_get_status/<run_id>')
def _get_status(run_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)
    
    # if re.match('^[0-9a-fA-F]{24}$', run_id) is None:
    #     return error('Invalid run id: %s' % run_id)
        
    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)
    run = runs[0]

    return json.dumps({'status': run['status']})

@app.route('/_set_status/<run_id>/<worker_id>/<status>', methods=['POST'])
def _set_status(run_id, worker_id, status):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=ObjectId(run_id))
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)
    
    # TODO: add module / offset status
    if status not in ['RUNNING', 'ERROR', 'FINISHED']:
        return error('Invalid status: %s' % status)    

    run = runs[0]
    if worker_id.isdigit():
        worker_id = int(worker_id)
    else:
        worker_id = 0
    if worker_id < run.number_workers and worker_id >= 0:
        run.workers[worker_id] = status

    if all([ea in ['FINISHED', 'ERROR'] for ea in run.workers]):
        run.status = 'FINISHED'
        run.end_time = datetime.now()

    if all([ea ['RUNNING', 'ERROR'] for ea in run.workers]):
        run.status = 'RUNNING'
    
    run.save()

    return json.dumps({'status': run['status']})

# debug function
@app.route('/_get_status_worker/<run_id>/<worker_id>', methods=['GET'])
def get_status_worker(run_id, worker_id):

    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    run = runs[0]

    if worker_id.isdigit():
        worker_id = int(worker_id)
    else:
        worker_id = 0

    if worker_id < run.number_workers and worker_id >= 0:
        return json.dumps(run.workers[worker_id])
    else:
        return error("Invalid worker_id: "+str(worker_id))

@app.route('/_set_stats/<run_id>/<worker_id>', methods=['POST'])
def set_stats(run_id, worker_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    run = runs[0] 
    content = request.get_json()
    if worker_id.isdigit():
        worker_id = int(worker_id)
    else:
        worker_id = 0

    if worker_id < run.number_workers and worker_id >= 0:
        stats = content['stats']
        run.stats[worker_id] = run.stats[worker_id] + stats
        run.save()
        # print run.stats
    return json.dumps({'success': True, 'message': 'Successfully set stats.'})

#debug function
@app.route('/_remove_stats/<run_id>/<worker_id>', methods=['GET'])
def remove_stats(run_id, worker_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    run = runs[0] 
    if worker_id.isdigit():
        worker_id = int(worker_id)
    else:
        worker_id = 0
    if worker_id < run.number_workers and worker_id >= 0:
        run.stats[worker_id] = []
        run.save()
    return json.dumps(run.stats)

#debug function
@app.route('/_remove_all_stats/<run_id>', methods=['GET'])
def remove_all_stats(run_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    run = runs[0] 
    run.stats = []
    run.save()
    return json.dumps(run.stats)

@app.route('/_set_targets/<program_id>', methods=['POST'])
def set_targets(program_id):
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    content = request.get_json()
    targets = content['targets']
    program.targets = targets
    program.save()
    return json.dumps({'success': True, 'message': 'Successfully set targets.'})

# Debug function
@app.route('/_get_targets/<program_id>', methods=['GET'])
def get_targets(program_id):
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    return json.dumps(program.targets)

# Debug function
@app.route('/_remove_targets/<program_id>', methods=['GET'])
def remove_targets(program_id):
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    program.targets = []
    program.save()
    json.dumps({'success': True, 'message': 'Successfully removed targets.'})

@app.route('/_set_classification/<program_id>', methods=['POST'])
def set_classification(program_id):
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    content = request.get_json()
    classification = content['crash_classified']
    program.crashes_classified.append(classification)
    program.save()
    return json.dumps({'success': True, 'message': 'Successfully set classification.'})

# Debug function
@app.route('/_get_classification/<program_id>', methods=['GET'])
def get_classification(program_id):
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    return json.dumps(program.crashes_classified)

# Debug function
@app.route('/_remove_classification/<program_id>', methods=['GET'])
def remove_classification(program_id):
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    program.crashes_classified = []
    program.save()
    return json.dumps({'success': True, 'message': 'Successfully removed classification.'})



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