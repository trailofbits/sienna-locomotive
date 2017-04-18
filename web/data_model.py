from flask_mongoengine import MongoEngine

'''
DATA MODEL
'''

db = MongoEngine()

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
    errors = db.ListField(db.StringField())
    # stats
    stats = db.ListField(db.ListField(db.DictField()))
