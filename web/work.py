from multiprocessing import Process
from subprocess import Popen
import shlex
import time
import json
import sys
sys.path.append('C:\\Users\\Douglas\\Documents\\work\\sienna-locomotive\\fuzzci\\')
from winafl import get_mod_off

run_lookup = {}

def run_mod_off(data):
	cmd = shlex.split(data['cmd'])
	print cmd
	mod, off = get_mod_off()
	print mod, off
	return {'module': mod, 'offset':off }

run_lookup['mod_off'] = run_mod_off

class Worker(Process):
	def __init__(self, num, in_queue, out_queue, command_queue):
		super(Worker, self).__init__()
		self.command_queue = command_queue
		self.in_queue = in_queue
		self.out_queue = out_queue
		self.num = num

	def run(self):
		while True:
			data = self.in_queue.get(True)
			
			if data == None:
				break

			print 'WORKER %d GOT JOB' % self.num
			self.out_queue.put(json.dumps({
				'event': 'started', 
				'worker': self.num,
				'data': data}))
			data = run_lookup[data['type']](data)
			print 'WORKER %d FINISHED JOB' % self.num
			self.out_queue.put(json.dumps({
				'event': 'finished', 
				'worker': self.num,
				'data': data,
				'data': data}))
		print 'WORKER FINISHED'

class Manager(Process):
	def __init__(self, out_queue, in_queue):
		super(Manager, self).__init__()
		self.out_queue = out_queue
		# run = {
		# 	'cmd': 'sleep 1',
		# 	'job': '9',
		# 	'type': 'mod_off'
		# }
		# in_queue.put(run)

	def run(self):
		while True:
			status = self.out_queue.get(True)
			
			if status == None:
				break

			time.sleep(1)
			print 'STATUS:', status
		print 'MANAGER FINISHED'