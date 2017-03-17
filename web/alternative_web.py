from flask import Flask, request, g, escape, send_from_directory
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
        'path_winafl', 
        'path_dynamorio', 
        'path_winafl_working_dir', 
        'path_autoit_working_dir', 
        'path_windbg_dir', 
        'path_autoit_bin', 
        'path_radamsa_bin', 
        'path_vmfuzz', 
        'fuzzers', 
        'path_radamsa_working_dir']

    name = db.StringField()
    path_winafl = db.StringField()
    path_dynamorio = db.StringField()
    path_winafl_working_dir = db.StringField()
    path_autoit_working_dir = db.StringField()
    path_windbg_dir = db.StringField()
    path_autoit_bin = db.StringField()
    path_radamsa_bin = db.StringField()
    path_vmfuzz = db.StringField()
    fuzzers = db.ListField(db.StringField())
    path_radamsa_working_dir = db.StringField()

# vmfuzz parent class
class Program(db.Document):
    meta = {'allow_inheritance': True}

    def required(self):
        return [
            'arch',
            'using_autoit',
            'path_program',
            'program_name',
            'seed_pattern',
            'file_format']    

    # Required
    arch = db.StringField()
    using_autoit = db.BooleanField()
    path_program = db.StringField()
    program_name = db.StringField()
    seed_pattern = db.StringField()
    file_format = db.StringField()


class ProgramAutoIT(Program):
    def required(self):
        return [
            'arch',
            'using_autoit', # true
            'path_program',
            'program_name',
            'seed_pattern',
            'file_format',
            'path_autoit_script']

    # With Autoit
    path_autoit_script = db.StringField()

class ProgramCMD(Program):
    def required(self):
        return [
            'arch',
            'using_autoit', # false
            'path_program',
            'program_name',
            'seed_pattern',
            'file_format',
            'auto_close',
            'running_time',
            'program_params',]

    # Without Autoit
    auto_close = db.StringField()
    running_time = db.IntField()
    program_params = db.ListField(db.StringField())


class Run(db.Document):
    def required(self):
        return [
            'input_dir',
            'crash_dir',
            'modules_and_offsets',
            'fuzz_time',
            'job_type',
            'radamsa_number_files_to_create',
            'winafl_default_timeout',
            'winafl_last_path_timeout',
            'winafl_fuzzing_iteration',
            ]

     # WebApp
    input_dir = db.StringField()
    crash_dir = db.StringField()
    fuzz_time = db.IntField() # kill fuzzing after time (minutes)
    modules_and_offsets = db.ListField(db.ListField(db.StringField()))
    job_type = db.StringField()
    # radamsa
    radamsa_number_files_to_create = db.IntField()
    # winafl
    winafl_default_timeout = db.IntField()
    winafl_last_path_timeout = db.IntField()
    winafl_fuzzing_iteration = db.IntField()

'''
WEB ENDPOINTS
'''

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

@app.route('/add_sys', methods=['POST'])
def add_sys():
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

    sys = System(**config)
    sys.save()

    return json.dumps({'system_id': str(sys.id)})

'''
TASKS
'''



'''
MAIN
'''
if __name__ == '__main__':
    app.run(debug=True)