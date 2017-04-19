import json
import yaml

from mongoengine.queryset import NotUniqueError
from data_model import System, Program, ProgramCMD, ProgramAutoIT
from flask import Blueprint
from flask import request
from web_utils import error, is_hex

program_endpoints = Blueprint('program_endpoints', __name__)

@program_endpoints.route('/prog_add_gui', methods=['POST'])
def prog_add_gui():
    """
    Adds a program (GUI) config
    Args:
        yaml (str): yaml config of the program object
    Returns:
        json: id of the created program
    """
    config_str = request.form['yaml']
    try:
        config = yaml.load(config_str)
    except yaml.scanner.ScannerError, e:
        return error('YAML load failed with message: \n' + str(e))
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

@program_endpoints.route('/prog_add_cmd', methods=['POST'])
def prog_add_cmd():
    """
    Adds a program (CMD) config
    Args:
        yaml (str): yaml config of the program object
    Returns:
        json: id of the created program
    """
    config_str = request.form['yaml']
    try:
        config = yaml.load(config_str)
    except yaml.scanner.ScannerError, e:
        return error('YAML load failed with message: \n' + str(e))
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

@program_endpoints.route('/prog_list/<system_id>')
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

@program_endpoints.route('/prog_delete', methods=['POST'])
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

@program_endpoints.route('/prog_edit', methods=['POST'])
def prog_edit():
    program_id = request.form['program_id']

    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)
    if len(program) != 1:
        return error('Program with id not found: %s' % program_id)

    config_str = request.form['yaml']
    try:
        config = yaml.load(config_str)
    except yaml.scanner.ScannerError, e:
        return error('YAML load failed with message: \n' + str(e))

    program[0].modify(**config)
    return json.dumps({'success': True, 'message': 'Successfully edited %s' % program_id})
