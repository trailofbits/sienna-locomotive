from flask import Flask, request, g, escape, send_from_directory
from celery import Celery
# import fuzz
import sqlite3
import json
import time
import sys
import os

# sys.path.append('../fuzzci')
sys.path.append('C:\\Users\\Douglas\\Documents\\work\\sienna-locomotive\\fuzzci\\')
from winafl import get_mod_off, init_dirs, winafl

app = Flask('web')

app.config['CELERY_BROKER_URL'] = 'redis://192.168.1.6:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://192.168.1.6:6379/0'
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

DATABASE = 'sl.db'

def init_db(db):
	print 'init_db'
	with open('init.sql') as f:
		sql = f.read()
		db.executescript(sql)

def get_db():
	db = getattr(g, '_database', None)
	if db is None:
		db = sqlite3.connect(DATABASE)
		init_db(db)
		g._database = db
	return db

@app.teardown_appcontext
def close_connection(exception):
	db = getattr(g, '_database', None)
	if db is not None:
		db.close()

@app.route('/')
def root():
    return send_from_directory('pub', 'index.html')

@app.route('/js/<path:path>')
def send_js(path):
    return send_from_directory('pub/js', path)

@app.route('/css/<path:path>')
def send_css(path):
    return send_from_directory('pub/css', path)

def get_data():
	return request.form

def check_params(keys, params):
	missing = []
	for ea in keys:
		if ea not in params or params[ea] in [None, '']:
			missing.append(ea)
	return missing

@app.route('/schema')
def get_schema():
	schema = {
		'winafl_job': winafl_job_schema(),
		'run': run_schema(),
		'type': ['winafl']
	}
	return json.dumps(schema)

def error(msg):
	return json.dumps({'error': True, 'message': msg})

@app.route('/task_status/<task_id>')
def task_status(task_id):
	task = task_mod_off.AsyncResult(task_id)
	return task.state

'''
WinAFL Job
'''

def winafl_keys():
	return winafl_job_schema()['order']

def winafl_job_schema():
	winafl_job_schema = {
		'order': ['id', 'name', 'command', 'file', 'module', 'offset', 'nargs', 'timeout'],
		'id': {
			'required': True,
			'type': 'num'
		},
		'name': {
			'required': True,
			'type': 'str'
		},
		'command': {
			'required': True,
			'type': 'text'
		},
		'file': {
			'required': True,
			'type': 'text'
		},
		'module': {
			'required': False,
			'type': 'str'
		},
		'offset': {
			'required': False,
			'type': 'num'
		},
		'nargs': {
			'required': False,
			'type': 'num'
		},
		'timeout': {
			'required': False,
			'type': 'str'
		}
	}
	return winafl_job_schema

# create cmd file based
@app.route('/winafl_job_create', methods=['POST'])
def winafl_job_create():
	data = get_data()

	schema = winafl_job_schema()
	keys = schema['order']
	
	missing = check_params(keys, data)
	missing = [key for key in missing if schema[key]['required'] and key != 'id']
	if len(missing) > 0:
		return error('Missing required argument(s): %s' % (', '.join(missing)))

	# have to dynamically generate the sql query
	# sqlite does not convert explicit null to default col value
	# have to filter out any empty strings in the request
	data = dict(data)
	reduced_keys = [key for key in keys if key != 'id' and data[key][0] != '']
	values = [data[key][0] if data[key][0] != '' else None for key in reduced_keys if key != 'id']
	query = 'INSERT INTO winafl_jobs (' + ', '.join(reduced_keys) + ') VALUES (' + ', '.join(['?'] * len(reduced_keys)) + ')'

	db = get_db()
	cur = db.cursor()
	cur.execute(query, values)
	db.commit()
	return winafl_job_list()

@app.route('/winafl_job_remove', methods=['POST'])
def winafl_job_remove():
	data = get_data()
	keys = ['id']
	missing = check_params(keys, data)

	if len(missing) > 0:
		# make bad request
		return error('Missing required argument(s): %s' % (', '.join(missing)))

	values = [data[ea] for ea in keys]
	print values
	db = get_db()
	cur = db.cursor()
	cur.execute('DELETE FROM winafl_jobs WHERE rowid=?', values)
	db.commit()
	return winafl_job_list()

def split_cmd(cmd):
	quotes = False
	split = []
	curr = r''
	for ch in cmd:
		if ch == ' ' and not quotes:
			split.append(curr)
			curr = r''
		else:
			if ch == '"':
				quotes = not quotes
			curr += ch
	split.append(curr)
	split = [ea.strip('"') for ea in split]
	return split

@celery.task
def task_mod_off(rowid, cmd):
	print cmd
	result = get_mod_off(cmd)
	print type(result)
	if type(result) is tuple:
		mod, off = result
		with app.app_context():
			db = get_db()
			cur = db.cursor()
			cur.execute('UPDATE winafl_jobs SET module = ?, offset = ? WHERE rowid = ?', [mod, off, rowid])
			db.commit()
	return result

# get mod off
@app.route('/winafl_job_mod_off', methods=['POST'])
def winafl_job_mod_off():
	data = get_data()
	keys = ['id']
	missing = check_params(keys, data)

	if len(missing) > 0:
		# make bad request
		return error('Missing required argument(s): %s' % (', '.join(missing)))

	values = [data[ea] for ea in keys]
	db = get_db()
	cur = db.cursor()
	cur.execute('SELECT command FROM winafl_jobs WHERE rowid = ?', values)
	results = cur.fetchall()
	if len(results) != 1:
		return error('Job not found!')

	cmd = results[0][0]
	print cmd
	task = task_mod_off.apply_async(args=[values[0], split_cmd(cmd)])
	print task.id
	print dir(task)
	return json.dumps({'task_id': task.id})

@app.route('/winafl_job_list')
def winafl_job_list():
	db = get_db()
	cur = db.cursor()
	cur.execute('SELECT rowid, * FROM winafl_jobs')
	lresults = cur.fetchall()
	print lresults
	keys = winafl_keys()
	dresults = [dict(zip(keys, res)) for res in lresults]
	return json.dumps(dresults)

'''
WinAFL Run
'''
def run_keys():
	return run_schema()['order']

def run_schema():
	run_schema = {
		'order': [
			'id', 'job_id', 'job_type', 'start_time', 'end_time', 
			'time_limit', 'crashes', 'hangs', 'in_dir', 'out_dir' ],
		'id': {
			'required': True,
			'type': 'num'
		},
		'job_id': {
			'required': True,
			'type': 'num'
		},
		'job_type': {
			'required': True,
			'type': 'num'
		},
		'start_time': {
			'required': False,
			'type': 'date'
		},
		'end_time': {
			'required': False,
			'type': 'date'
		},
		'time_limit': {
			'required': False,
			'type': 'num'
		},
		'crashes': {
			'required': False,
			'type': 'num'
		},
		'hangs': {
			'required': False,
			'type': 'num'
		},
		'in_dir': {
			'required': False,
			'type': 'text'
		},
		'out_dir': {
			'required': False,
			'type': 'text'
		}
	}
	return run_schema

@app.route('/run_list')
def run_list():
	db = get_db()
	cur = db.cursor()
	cur.execute('SELECT rowid, * FROM runs')
	lresults = cur.fetchall()
	keys = run_keys()
	dresults = [dict(zip(keys, res)) for res in lresults]
	return json.dumps(dresults)

@app.route('/winafl_run_create', methods=['POST'])
def winafl_run_create():
	data = get_data()
	keys = ['job_id']
	
	missing = check_params(keys, data)
	missing = [key for key in missing if schema[key]['required'] and key != 'id']
	if len(missing) > 0:
		return error('Missing required argument(s): %s' % (', '.join(missing)))

	# query job
	# get file
	# init_dirs(file)
	# copy file to in_dir

	# future: copy corpus

	job_id = data['job_id']
	values = [job_id, 0]
	query = 'INSERT INTO runs (job_id, job_type) VALUES (?, ?)'

	db = get_db()
	cur = db.cursor()
	cur.execute(query, values)
	db.commit()
	return run_list()

@app.route('/run', methods=['POST'])
def run():
	# required run_id
	# query run_cmd, config
	# winafl(run_cmd, config)
	pass

# create run
	# create run folder
		# create in dir
		# creat out dir
		# copy input file
		# copy corpus
	# store in database

# run run

# create gui / autoit

# gracefully stop?
	# send kill command via command array

if __name__ == '__main__':
	app.run(debug=True)
