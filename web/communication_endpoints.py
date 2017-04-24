'''
COMMUNICATION
'''
import json
import yaml

from datetime import datetime
from bson.objectid import ObjectId
from data_model import Run, Program
from flask import Blueprint
from flask import request
from web_utils import is_hex, error

import ansible_command

communication_endpoints = Blueprint('communication_endpoints', __name__)

with open('config.yaml') as config_file:
    contents = config_file.read()
    WEB_CONFIG = yaml.load(contents)

@communication_endpoints.route('/_get_status/<run_id>')
def _get_status(run_id):
    """
    Get the status of a run
    Used for terminating the run
    Args:
        run_id (str): id of the run config
    Returns:
        json: status of the run
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)
    run = runs[0]

    return json.dumps({'status': run['status']})

@communication_endpoints.route('/_set_status_exploitable/<run_id>/<worker_id>/<status>', methods=['POST'])
def _set_status_exploitable(run_id, worker_id, status):
    """
    Set the worker status of a triage run
    Args:
        run_id (str): id of the run config
        worker_id (str): id of the worker
        status (str): status of the worker
    Returns:
        json: status of the run
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=ObjectId(run_id))
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)

    if status not in ['RUNNING', 'ERROR', 'FINISHED']:
        return error('Invalid status: %s' % status)

    run = runs[0]
    if worker_id.isdigit():
        worker_id = int(worker_id)
    else:
        worker_id = 0

    if worker_id < run.number_workers and worker_id >= 0:
        run.crash_workers[worker_id] = status

    if all([ea in ['FINISHED', 'ERROR'] for ea in run.workers]):
        run.status = 'FINISHED'

        if 'ANSIBLE_STOP_VM' in WEB_CONFIG:
            prog = run['program']
            ansible_command.command_vms(
                WEB_CONFIG['ANSIBLE_STOP_VM'], prog['vmtemplate'],
                str(run['id']),
                run['number_workers'])

    elif all([ea in ['RUNNING', 'ERROR'] for ea in run.workers]):
        run.status = 'TRIAGE'

    run.save()

    return json.dumps({'status': run['status']})

@communication_endpoints.route('/_set_status/<run_id>/<worker_id>/<status>', methods=['POST'])
def _set_status(run_id, worker_id, status):
    """
    Set the worker status of a fuzzing run
    Args:
        run_id (str): id of the run config
        worker_id (str): id of the worker
        status (str): status of the worker
    Returns:
        json: status of the run
    """
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

        if 'ANSIBLE_STOP_VM' in WEB_CONFIG:
            prog = run['program']
            ansible_command.command_vms(
                WEB_CONFIG['ANSIBLE_STOP_VM'], prog['vmtemplate'],
                str(run['id']),
                run['number_workers'])

    elif all([ea in ['RUNNING', 'ERROR'] for ea in run.workers]):
        run.status = 'RUNNING'

    run.save()

    return json.dumps({'status': run['status']})

@communication_endpoints.route('/_set_error/<run_id>/<worker_id>', methods=['POST'])
def set_error(run_id, worker_id):
    """
    Set the error for a worker
    Args:
        run_id (str): id of the run config
        worker_id (str): id of the worker
        msg (str): error message
    Returns:
        json: success message
    """
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
        msg = content['msg']
        run.errors[worker_id] = msg
        run.save()

        # print run.stats
    return json.dumps({'success': True, 'message': 'Successfully set error.'})

# debug function
@communication_endpoints.route('/_get_status_worker/<run_id>/<worker_id>', methods=['GET'])
def get_status_worker(run_id, worker_id):
    """
    Get a worker's status
    Args:
        run_id (str): id of the run config
        worker_id (str): id of the worker
    Returns:
        json: status of the worker
    """

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
        return error("Invalid worker_id: " + str(worker_id))

@communication_endpoints.route('/_set_stats/<run_id>/<worker_id>', methods=['POST'])
def set_stats(run_id, worker_id):
    """
    Update stats for a run
    Args:
        run_id (str): id of the run config
        worker_id (str): id of the worker
        stats (dict): stats of the worker
    Returns:
        json: success message
    """
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
        run.stats[worker_id] = run.stats[worker_id] + [stats]
        run.save()
        # print run.stats

    return json.dumps({'success': True, 'message': 'Successfully set stats.'})

#debug function
@communication_endpoints.route('/_remove_stats/<run_id>/<worker_id>', methods=['GET'])
def remove_stats(run_id, worker_id):
    """
    Clears the stats for a worker
    Args:
        run_id (str): id of the run config
        worker_id (str): id of the worker
    Returns:
        json: empty stats
    """

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
@communication_endpoints.route('/_remove_all_stats/<run_id>', methods=['GET'])
def remove_all_stats(run_id):
    """
    Clears the stats for all workers
    Args:
        run_id (str): id of the run config
    Returns:
        json: empty run stats
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    run = runs[0]
    run.stats = []

    for worker_id in xrange(run['number_workers']):
        run.stats.append([])
    run.save()

    return json.dumps(run.stats)

@communication_endpoints.route('/_set_targets/<program_id>', methods=['POST'])
def set_targets(program_id):
    """
    Set the target modules and offsets of a program
    Args:
        program_id (str): id of the program config
        targets (dict): discovered modules, offsets, and coverage modules
    Returns:
        json: success message
    """
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    content = request.get_json()
    targets = content['targets']
    program.targets = targets
    program.save()

    return json.dumps({'success': True, 'message': 'Successfully set targets.'})

# Debug function
@communication_endpoints.route('/_get_targets/<program_id>', methods=['GET'])
def get_targets(program_id):
    """
    Retrieve the targets for a program
    Args:
        program_id (str): id of the progam config
    Returns:
        json: program targets
    """
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]

    return json.dumps(program.targets)

# Debug function
@communication_endpoints.route('/_remove_targets/<program_id>', methods=['GET'])
def remove_targets(program_id):
    """
    Clears the targets of a program
    Args:
        program_id (str): id of the progam config
    Returns:
        json: success message
    """
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    program.targets = []
    program.save()

    return json.dumps({'success': True, 'message': 'Successfully removed targets.'})

@communication_endpoints.route('/_set_classification/<run_id>', methods=['POST'])
def set_classification(run_id):
    """
    Sets the classification of a crash
    Args:
        run_id (str): id of the run config
        crash_classified (dict): dictionary containing the crash name and classification
    Returns:
        json: success message
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    run = Run.objects(id=run_id)[0]
    print run
    content = request.get_json()
    crash = content['crash_classified']
    if 'crash_classifications' not in run:
        run['crash_classifications'] = {}

    run.crash_classifications[crash['crash_file'].replace('.', '_')] = crash['classification']
    run.save()

    return json.dumps({'success': True, 'message': 'Successfully set classification.'})

# Debug function
@communication_endpoints.route('/_get_classification/<run_id>', methods=['GET'])
def get_classification(run_id):
    """
    Return all crash classifications for a run
    Args:
        run_id (str): id of the run config
    Returns:
        json: crash classifications
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Program id invalid: %s' % run_id)

    run = Run.objects(id=run_id)
    return json.dumps(run.crash_classifications)

# Debug function
@communication_endpoints.route('/_remove_classification/<run_id>', methods=['GET'])
def remove_classification(run_id):
    """
    Clears the classifications of a run
    Args:
        run_id (str): id of the run config
    Returns:
        json: success message
    """
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    run = Run.objects(id=run_id)[0]
    run.update(unset__crash_classifications=1, unset__crash_workers=1)
    run.status = 'FINISHED'
    run.save()

    return json.dumps({'success': True, 'message': 'Successfully removed classification.'})

