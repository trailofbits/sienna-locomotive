'''
COMMUNICATION
'''
import json

from datetime import datetime
from bson.objectid import ObjectId
from data_model import Run, Program
from flask import Blueprint
from flask import request
from web_utils import is_hex, error

communication_endpoints = Blueprint('communication_endpoints', __name__)

@communication_endpoints.route('/_get_status/<run_id>')
def _get_status(run_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    if len(runs) != 1:
        return error('No run found with id: %s' % run_id)
    run = runs[0]

    return json.dumps({'status': run['status']})

@communication_endpoints.route('/_set_status/<run_id>/<worker_id>/<status>', methods=['POST'])
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

    if all([ea in ['RUNNING', 'ERROR'] for ea in run.workers]):
        run.status = 'RUNNING'

    run.save()

    return json.dumps({'status': run['status']})

@communication_endpoints.route('/_set_error/<run_id>/<worker_id>', methods=['POST'])
def set_error(run_id, worker_id):
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

@communication_endpoints.route('/_set_stats/<run_id>/<worker_id>', methods=['POST'])
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
@communication_endpoints.route('/_remove_stats/<run_id>/<worker_id>', methods=['GET'])
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
@communication_endpoints.route('/_remove_all_stats/<run_id>', methods=['GET'])
def remove_all_stats(run_id):
    if len(run_id) not in [12, 24] or not is_hex(run_id):
        return error('Run id invalid: %s' % run_id)

    runs = Run.objects(id=run_id)
    run = runs[0]
    run.stats = []
    run.save()
    return json.dumps(run.stats)

@communication_endpoints.route('/_set_targets/<program_id>', methods=['POST'])
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
@communication_endpoints.route('/_get_targets/<program_id>', methods=['GET'])
def get_targets(program_id):
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    return json.dumps(program.targets)

# Debug function
@communication_endpoints.route('/_remove_targets/<program_id>', methods=['GET'])
def remove_targets(program_id):
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    program.targets = []
    program.save()
    json.dumps({'success': True, 'message': 'Successfully removed targets.'})

@communication_endpoints.route('/_set_classification/<program_id>', methods=['POST'])
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
@communication_endpoints.route('/_get_classification/<program_id>', methods=['GET'])
def get_classification(program_id):
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    return json.dumps(program.crashes_classified)

# Debug function
@communication_endpoints.route('/_remove_classification/<program_id>', methods=['GET'])
def remove_classification(program_id):
    if len(program_id) not in [12, 24] or not is_hex(program_id):
        return error('Program id invalid: %s' % program_id)

    program = Program.objects(id=program_id)[0]
    program.crashes_classified = []
    program.save()
    return json.dumps({'success': True, 'message': 'Successfully removed classification.'})

