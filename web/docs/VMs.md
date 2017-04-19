VMs deployment
==============

VMs can be deployed in:
- Virtualbox, for dev purpose, without creating a new VM at each run (tested on Ubuntu, as host)
- VMware (tested using ESXI and vcenter, using nested virtualization)


**Template**

A VM template containing `vmfuzz` and the targeted program has to be provided. Please refer to the [vmfuzz installation guidelines](../vmfuzz/Install.md).

- On virtualbox, a VM is a template. Create a snapshot of the VM called `startup` (when the VM is poweroff)
- On vmware, a VM can be converted to a template using vcenter.


The name of the template has to be provided in the `program` configuration (the `vmtemplate` field)

**VM Startup**

Please create `startup.bat` in the `shell:startup` directory of Windows of the template,; which launches the celery worker at the startup:
```batch
X: 
cd X:\path_to_sienna_locomotive\web
celery -A web.celery worker -n worker%RANDOM%@%h
```

``X:`` is used if the script in not in the C: directory


` -n worker%RANDOM%@%h `is used to set a random hostname to the worker


A first start of the VM is needed to allow the launch of the script at the startup.



**Ansible**

[Ansible](http://docs.ansible.com/ansible/intro_installation.html) is used to automatize the deployment of virtual machines.

- When a run is added, the ansible script located in `ANSIBLE_START_VM` (`web/config.yaml`) is called
- When a run is stopped, the ansible script located in `ANSIBLE_STOP_VM` (`web/config.yaml`) is called

**Virtualbox Deployment (dev)**

As cloning VM can be slow, VMs are not created at each new run. 
Instead, you must create several clones of the `vmtemplate`, named `<template_name>_0`, `<template_name>_1`, ...

Then add in `web/config.yaml`:
```yaml
ANSIBLE_START_VM:
    "../ansible/virtualbox/create_vms.yaml"
ANSIBLE_STOP_VM:
    "../ansible/virtualbox/stop_vms.yaml"
``` 

**Vmware Deployment**

For each run, a new VM is created from the template, named `<template_name>_<run_id>_<worker_id>`.
The VM is deleted when the run stopped.


Add in `web/config.yaml`
```yaml
ANSIBLE_START_VM:
    "../ansible/nested_esxi/create_vms.yaml"
ANSIBLE_STOP_VM:
    "../ansible/nested_esxi/stop_vms.yaml"
``` 

Then create `../ansible/nested_esxi/config_esxi.yaml`:
```yaml
ipesxi:
    X.X.X.X
ipvcenter:
    Y.Y.Y.Y
username:
    administrator@vsphere.local
rootpassword:
    password
``` 
