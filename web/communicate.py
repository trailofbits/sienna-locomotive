import requests
import json

# @app.route('/_get_status/<run_id>')
# def _get_status(run_id):
#     runs = Run.objects(id=run_id)
#     if len(runs) != 1:
#         return error('No run found with id: %s' % run_id)
#     run = runs[0]

#     return json.dumps({'status': run['status']})

# @app.route('/_set_status/<run_id>/<worker_id>/<status>')
# def _set_status(run_id, worker_id, status):
#     runs = Run.objects(id=run_id)
#     if len(runs) != 1:
#         return error('No run found with id: %s' % run_id)
    
#     worker_id = int(worker_id)

#     if status not in ['STARTED', 'ERROR', 'STOPPED']:
#         return error('Invalid status: %s' % status)    

#     run = runs[0]
#     run.workers[worker_id] = status

#     if all([ea == 'STOPPED' for ea in run.workers]):
#         run['status'] = 'STOPPED'

#     if all([ea == 'STARTED' for ea in run.workers]):
#         run['status'] = 'RUNNING'

#     run.save()

#     return json.dumps({'status': run['status']})

def get_status(run_id):
    resp = requests.get('http://localhost:5000/_get_status/' + run_id)
    return resp.json()

def set_status(run_id, worker_id, status):
    tail = '%d/%d/%s' % (int(run_id), int(worker_id), status)
    resp = requests.post('http://localhost:5000/_set_status/' + tail)
    return resp.json()