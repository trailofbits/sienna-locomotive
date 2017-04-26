# Ansible Configuration

[Ansible](http://docs.ansible.com/ansible/intro_installation.html) is used to automatize the deployment of virtual machines.

- When a run is added, the ansible script located in `create_vms.yaml` is called
- When a run is stopped, the ansible script located in `stop_vms.yaml` is called

## Provided Set of Scripts

### Vmware Deployment



The directory [ansible/esxi](../ansible/esxi/) contains the scripts for an architecture based on vcenter and esxi (tested on a nested virtualization). 

- Update the file `ansible/esxi/config.yaml`with the proper values.
- Convert your VM into a template, using vcenter.

> **Note**: The name of the template is asked during the program configuration (`vmtemplate`), 


> **Note**: During the configuration of the webapp (`web/config.yaml`), you need to add:
> ```yaml
> ANSIBLE_START_VM:
>    "../ansible/esxi/create_vms.yaml"
> ANSIBLE_STOP_VM:
>     "../ansible/esxi/stop_vms.yaml"
> ``` 

### Virtualbox Deployment 

The directory [ansible/virtualbox](../ansible/virtualbox/) contains the scripts for an architecture based on virtualbox (tested on Ubuntu 16.04).

As cloning VM can be slow, VMs are not created at each new run. 
Instead, you must, before the run, create several clones of the original VM, named `<template_name>_0`, `<template_name>_1`, ...

> **Note**: The basename of the templates (`<template_name>`) is asked during the program configuration (`vmtemplate`), 

> **Note**: During the configuration of the webapp (`web/config.yaml`), you need to add:
> ```yaml
> ANSIBLE_START_VM:
>    "../ansible/virtualbox/create_vms.yaml"
> ANSIBLE_STOP_VM:
>     "../ansible/virtualbox/stop_vms.yaml"
> ``` 


## Building New Ansible Script

The scripts are called with three parameters:
- `template`: the name of the VM template
- `run_id`: the id of the run
- `number_worker`: the number of workers (i.e. the number of VM clones)
