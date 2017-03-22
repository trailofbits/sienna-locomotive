from flask import Flask, request, g, escape, send_from_directory
from mongoengine.queryset import NotUniqueError
from flask_mongoengine import MongoEngine
from celery.result import AsyncResult
from celery import Celery
import json
import yaml

'''
INITIALIZATION
'''

app = Flask('web')

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
            'program_params',]

    # Without Autoit
    auto_close = db.BooleanField()
    running_time = db.IntField()
    program_params = db.ListField(db.StringField())


class Run(db.Document):
    required = [
            'name',
            'input_dir',
            'crash_dir',
            'winafl_targets',
            'fuzz_time',
            'job_type',
            'radamsa_number_files_to_create',
            'winafl_default_timeout',
            'winafl_last_path_timeout',
            'winafl_fuzzing_iteration',
            'program']

    required_all = [
            'name',
            'input_dir',
            'crash_dir',
            'job_type',
            'program']

    # all
    program = db.ReferenceField(Program)
    name = db.StringField()
    job_type = db.StringField()
    # WebApp
    input_dir = db.StringField()
    crash_dir = db.StringField()
    fuzz_time = db.IntField() # kill fuzzing after time (minutes)
    # radamsa
    radamsa_number_files_to_create = db.IntField()
    # winafl
    winafl_default_timeout = db.IntField()
    winafl_last_path_timeout = db.IntField()
    winafl_fuzzing_iteration = db.IntField()
    winafl_targets = db.ListField(db.ListField(db.StringField()))


'''
WEB ENDPOINTS
'''

# MISC

def error(msg):
    return json.dumps({'error': True, 'message': msg})

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
    print config

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
    systems = [sys.to_mongo().to_dict() for sys in System.objects()]
    print systems
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
    print config

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
    print config

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
    print programs_gui
    for prog in programs_gui:
        prog['_id'] = str(prog['_id'])
        prog['system'] = str(prog['system'])

    programs_cmd = [prog.to_mongo().to_dict() for prog in ProgramCMD.objects(system=system_id)]
    print programs_cmd
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


'''
TASKS
'''



'''
MAIN
'''
if __name__ == '__main__':
    app.run(debug=True)