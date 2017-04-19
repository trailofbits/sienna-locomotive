""" Module handling the launch of the ansible playbook"""

import subprocess

def command_vms(ansible_script, template, run_id, number_worker):
    cmd = ['ansible-playbook', ansible_script , '--extra-vars','{"template":"'+template+'","run_uid":"'+run_id+'","number_worker":'+str(number_worker)+'}',"-vvvv"]
    print cmd
    proc = subprocess.Popen(cmd)
    proc.wait()
    
