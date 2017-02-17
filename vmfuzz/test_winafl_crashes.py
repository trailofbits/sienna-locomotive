import os
import shutil
import exploitable_standalone

'''
Writes each crash in crash_dir to target_file, 
invokes !exploitable, and prints the results.
'''
def process_winafl_crashes(config, crash_dir, target_file):
	last_c = ''
	for ea in os.listdir(crash_dir):
		if not ea.startswith('id_'):
			continue
		full_path = os.path.join(crash_dir, ea)
		shutil.copy(full_path, target_file)
		verdict = exploitable_standalone.run(
			config['prog_path'], config['prog_name'], config['args'])
		print ea, verdict

def main():
	crash_dir = r'C:\Users\Douglas\Documents\work\fuzz\oldout\crashes_20170212133053'
	target_file = r"C:\Users\Douglas\Desktop\sigs.ldb"
	config = {
		'prog_path': r"C:\Program Files\ClamAV-x64", 
		'prog_name': "clamscan.exe",
		'args': ['-d', target_file, "C:\Program Files\ClamAV-x64\clambc.exe"]
	}
	process_winafl_crashes(config, crash_dir, target_file)

if __name__ == '__main__':
	main()