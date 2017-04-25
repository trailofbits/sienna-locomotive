# Ansible Configuration

Ansible is used to tune the VM deployement to any cloud architecture. 

Two Ansible scripts are required:
- `create_vms.yaml`:  clone and start a virtual machine 
- `stop_vms.yaml`: stop and remove the virtual machine

## Provided Set of Scripts

- `esxi`: vcenter and esxi architecture (tested on nested virtualisation)
    - Update `esxi/config.yaml`with the proper values
- `virtualbox`: virtualbox architecture (tested on Ubuntu host, using snapshot)

## Building New Ansible Script

The scripts are called with three parameters:
- `template`: the name of the VM template
- `run_id`: the id of the run
- `number_worker`: the number of workers (i.e. the number of VM clones)
