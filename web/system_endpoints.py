from mongoengine.queryset import NotUniqueError
from data_model import System
from flask import Blueprint
from flask import request
import yaml
import json

system_endpoints = Blueprint('system_endpoints', __name__)

@system_endpoints.route('/sys_add', methods=['POST'])
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
        system = System(**config)
        system.save()
    except NotUniqueError:
        return error('Name already in use: %s' % config['name'])

    return json.dumps({'system_id': str(system.id)})

@system_endpoints.route('/sys_list')
def sys_list():
    """
    List available system configs
    Returns:
        json: list of systems
    """
    objs = System.objects()
    if len(objs) < 1:
        return json.dumps([])

    systems = [system.to_mongo().to_dict() for system in objs]
    # print systems
    for system in systems:
        system['_id'] = str(system['_id'])

    systems_info = {'order': System.required, 'systems': systems}
    return json.dumps(systems_info)

@system_endpoints.route('/sys_delete', methods=['POST'])
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

@system_endpoints.route('/sys_edit', methods=['POST'])
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
