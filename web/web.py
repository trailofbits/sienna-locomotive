from flask import Flask, request, g, escape, send_from_directory
from multiprocessing import Queue
from work import Worker, Manager
# import fuzz
import sqlite3
import json
import sys
import os

sys.path.append('../fuzzci')
import winafl

app = Flask('Sienna Locomotive 2')
DATABASE = 'sl.db'

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
	data = {
		'cmd': cmd,
		'job': values[0],
		'type': 'mod_off'
	}
	in_queue.put(data)
	out_queue.put('HELLO')
	# send command to worker
	# update db when finished
	return winafl_job_list()


NUM_WORKERS = 2
def init_workers():
	global pool
	global cmds
	global in_queue
	global out_queue
	global manager

	pool = []
	cmds = []
	
	in_queue = Queue()
	out_queue = Queue()
	
	for idx in xrange(NUM_WORKERS):
		command_queue = Queue()
		pool.append(Worker(idx, in_queue, out_queue, command_queue))
		pool[-1].start()
		cmds.append(command_queue)

	manager = Manager(out_queue, in_queue)
	manager.start()

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
	for worker in pool:
		in_queue.put(None)
	for worker in pool:
		worker.terminate()
	out_queue.put(None)
	manager.terminate()

@app.route('/')
def root():
    return send_from_directory('pub', 'index.html')

@app.route('/js/<path:path>')
def send_js(path):
    return send_from_directory('pub/js', path)

@app.route('/css/<path:path>')
def send_css(path):
    return send_from_directory('pub/css', path)

# @app.route('/retest/', defaults={'target': None})
# @app.route('/retest/<target>')
# def retest(target):
#     # TODO: this should be in a worker
#     os.chdir('../sample/')
#     if target is None:
#         results = fuzz.test_all_targets()
#     else:
#         results = fuzz.test_one_target(target)

#     return json.dumps(results)


def get_data():
	return request.form

def check_params(keys, params):
	missing = []
	for ea in keys:
		if ea not in params or params[ea] in [None, '']:
			missing.append(ea)
	return missing

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

def error(msg):
	return json.dumps({'error': True, 'message': msg})

@app.route('/schema')
def get_schema():
	schema = {
		'winafl_job': winafl_job_schema(),
	}
	return json.dumps(schema)

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

	values = [data[key] for key in keys if key != 'id']
	# print len(values)
	db = get_db()
	cur = db.cursor()
	cur.execute('INSERT INTO winafl_jobs (name, command, file, module, offset, nargs, timeout) VALUES (?, ?, ?, ?, ?, ?, ?)', values)
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

@app.route('/winafl_job_list')
def winafl_job_list():
	db = get_db()
	cur = db.cursor()
	cur.execute('SELECT rowid, * FROM winafl_jobs')
	lresults = cur.fetchall()
	keys = winafl_keys()
	dresults = [dict(zip(keys, res)) for res in lresults]
	return json.dumps(dresults)

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
	init_workers()
	app.run(debug=True)
