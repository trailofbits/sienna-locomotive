from flask import Flask, request, g, escape, send_from_directory, redirect
from mongoengine.queryset import NotUniqueError
from werkzeug.utils import secure_filename
from flask_mongoengine import MongoEngine
from celery.result import AsyncResult
from celery import Celery
import shutil
import json
import time
import yaml
import sys
import os
import re

sys.path.append('C:\\Users\\dougl\\Documents\\sienna-locomotive\\vmfuzz\\')
import vmfuzz

'''
INITIALIZATION
'''

app = Flask('alternative_web')

app.config['MONGODB_SETTINGS'] = {
    'db': 'fuzzdb',
    'host': '192.168.1.6',
    'port': 27017
}
db = MongoEngine(app)

app.config['CELERY_BROKER_URL'] = 'redis://192.168.1.6:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://192.168.1.6:6379/0'
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# input_crashes from the web app's view
PATH_SHARED_INPUT_CRASHES = 'X:\\input_crashes'

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
            'seed_pattern',
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


class ProgramAutoIT(Program):
    required = [
            'name',
            'arch',
            'using_autoit', # true
            'path_program',
            'program_name',
            'seed_pattern',
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
            'seed_pattern',
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



'''
WEB ENDPOINTS
'''

# MISC

def error(msg):
    return json.dumps({'error': True, 'message': msg})

def mkdir_ifne(path):
    if not os.path.exists(path):
        os.mkdir(path)

@app.route('/')
def root():
    return send_from_directory('pub', 'index.html')

@app.route('/js/<path:path>')
def send_js(path):
    return send_from_directory('pub/js', path)

@app.route('/css/<path:path>')
def send_css(path):
    return send_from_directory('pub/css', path)

def is_hex(target):
    return all(ch in 'ABCDEFabcdef0123456789' for ch in target)

# SYSTEM

@app.route('/sys_add', methods=['POST'])
def sys_add():
    config_str = request.form['yaml']
    config = yaml.load(config_str)
    # print config

    missing = []
    for key in System.required:
        if key not in config:
            missing.append(key)    

    if len(missing) != 0:
        return error('Missing required fields: %s' % ' '.join(missing))

    for key in config:
        if key not in System.required:
            config.pop(key, None)

    try:
        sys = System(**config)
        sys.save()
    except NotUniqueError:
        return error('Name already in use: %s' % config['name'])

    return json.dumps({'system_id': str(sys.id)})

@app.route('/sys_list')
def sys_list():
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
    # TODO: Delete all programs, runs associated
    system_id = request.form['system_id']
    system = System.objects(id=system_id)
    if len(system) != 1:
        return error('System with id not found: %s' % system_id)
    system[0].delete()
    return json.dumps({'success': True, 'message': 'Successfully deleted %s' % system_id})

@app.route('/sys_edit', methods=['POST'])
def sys_edit():
    system_id = request.form['system_id']

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
    config_str = request.form['yaml']
    config = yaml.load(config_str)
    # print config

    missing = []
    for key in ProgramAutoIT.required:
        if key not in config:
            missing.append(key)    

    if len(missing) != 0:
        return error('Missing required fields: %s' % ' '.join(missing))

    for key in config:
        if key not in ProgramAutoIT.required:
            config.pop(key, None)

    try:
        prog = ProgramAutoIT(**config)
        prog.save()
    except NotUniqueError:
        return error('Name already in use: %s' % config['name'])

    return json.dumps({'program_id': str(prog.id)})

@app.route('/prog_add_cmd', methods=['POST'])
def prog_add_cmd():
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

    for key in config:
        if key not in ProgramCMD.required:
            config.pop(key, None)

    try:
        prog = ProgramCMD(**config)
        prog.save()
    except NotUniqueError:
        return error('Name already in use: %s' % config['name'])

    return json.dumps({'program_id': str(prog.id)})

@app.route('/prog_list/<system_id>')
def prog_list(system_id):
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
    program_id = request.form['program_id']
    program = Program.objects(id=program_id)
    if len(program) != 1:
        return error('Program with id not found: %s' % program_id)
    program[0].delete()
    return json.dumps({'success': True, 'message': 'Successfully deleted %s' % program_id})

@app.route('/prog_edit', methods=['POST'])
def prog_edit():
    program_id = request.form['program_id']

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
    config_str = request.form['yaml']
    config = yaml.load(config_str)
    # print config

    missing = []
    for key in Run.user_all:
        if key not in config:
            missing.append(key)    

    if len(missing) != 0:
        return error('Missing required fields: %s' % ' '.join(missing))

    if config['run_type'] not in ['all']:
        return error('Unsupported run type: %s' % ' '.join(config['run_type']))

    # get system path_input_crashes
    prog = Program.objects(id=config['program'])
    if len(prog) != 1:
        return error('Invalid program id: %s' % config['program'])
    sys = prog[0]['system']
    path_input_crashes = sys['path_input_crashes']

    # create input dir
    input_dir = 'input_%s' % hex(int(time.time()))[2:] 
    # create output dir
    crash_dir = 'crash_%s' % hex(int(time.time()))[2:]
    
    web_input_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, input_dir)
    web_crash_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, crash_dir)
    
    mkdir_ifne(web_input_dir)
    mkdir_ifne(web_crash_dir)

    vm_input_dir = os.path.join(path_input_crashes, input_dir)
    vm_crash_dir = os.path.join(path_input_crashes, crash_dir)

    config['input_dir'] = vm_input_dir
    config['crash_dir'] = vm_crash_dir

    for key in config:
        if key not in Run.required_all:
            config.pop(key, None)

    try:
        run = Run(**config)
        run.save()
    except NotUniqueError:
        return error('Name already in use: %s' % config['name'])

    return json.dumps({'run_id': str(run.id)})

@app.route('/run_list/<program_id>')
def run_list(program_id):
    runs = [run.to_mongo().to_dict() for run in Run.objects(program=program_id)]
    for run in runs:
        run['_id'] = str(run['_id'])
        run['program'] = str(run['program'])

    run_info = {'order': Run.required, 'runs': runs}
    return json.dumps(run_info)

# upload seed file
@app.route('/run_files_add', methods=['POST'])
def run_files_add():
    # copy file to input directory
    run_id = request.json['run_id']
    # print request.json['files']
    fnames = [secure_filename(fname) for fname in request.json['files']]

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
    # copy file to input directory
    run_id = request.json['run_id']
    # print request.json['files']
    fnames = [secure_filename(fname) for fname in request.json['files']]

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

@app.route('/run_files_list/<run_id>')
def run_files_list(run_id):
    run = Run.objects(id=run_id)
    if len(run) != 1:
        return error('Run with id not found: %s' % run_id)

    input_path = os.path.join(PATH_SHARED_INPUT_CRASHES, run[0].input_dir)
    flist = os.listdir(input_path)

    return json.dumps(flist)

@app.route('/run_start/<run_id>', methods=['POST'])
def run_start(run_id):
    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)

    run = runs[0].to_mongo().to_dict()
    run['_id'] = str(run['_id'])
    run['program'] = str(run['program'])
    # print run

    progs = Program.objects(id=run['program'])
    prog = progs[0].to_mongo().to_dict()

    prog['_id'] = str(prog['_id'])
    prog['system'] = str(prog['system'])
    # print prog

    syss = System.objects(id=prog['system'])
    sys = syss[0].to_mongo().to_dict()

    sys['_id'] = str(sys['_id'])
    # print sys

    for worker_id in xrange(1):
        task = task_run_start.apply_async(args=[sys, prog, run, worker_id])
        runs[0].workers.append('STARTED')
    runs[0]['status'] = 'STARTING'
    runs[0].save()
    # print task.id
    return json.dumps({'run_id': run['_id']})

@app.route('/run_stop/<run_id>', methods=['POST'])
def run_stop(run_id):
    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)
    
    runs[0]['status'] = 'STOPPING'
    runs[0].save()
    # print task.id
    return json.dumps({'run_id': run['_id']})

def run_get_system(run):
    prog = run['program']
    sys = prog['system']
    return sys

# CORPORA

@app.route('/corpus_files_list')
def corpus_files_list():
    corpus_dir = os.path.join(PATH_SHARED_INPUT_CRASHES, 'corpora')
    flist = os.listdir(corpus_dir)
    return json.dumps(flist)

@app.route('/corpora', methods=['GET', 'POST'])
def corpora():
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
def task_run_start(sys, prog, run, worker_id):
    vmfuzz.fuzz(sys, prog, run)

'''
COMMUNICATION
'''

@app.route('/_get_status/<run_id>')
def _get_status(run_id):
    if re.match('^[0-9a-fA-F]{24}$', run_id) is None:
        return error('Invalid run id: %s' % run_id)
        
    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)
    run = runs[0]

    return json.dumps({'status': run['status']})

@app.route('/_set_status/<run_id>/<worker_id>/<status>', methods=['POST'])
def _set_status(run_id, worker_id, status):
    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)
    
    worker_id = int(worker_id)

    if status not in ['STARTED', 'ERROR', 'STOPPED']:
        return error('Invalid status: %s' % status)    

    run = runs[0]
    run.workers[worker_id] = status

    if all([ea == 'STOPPED' for ea in run.workers]):
        run['status'] = 'STOPPED'

    if all([ea == 'STARTED' for ea in run.workers]):
        run['status'] = 'RUNNING'

    run.save()

    return json.dumps({'status': run['status']})


'''
MAIN
'''
if __name__ == '__main__':
    app.run(debug=True)