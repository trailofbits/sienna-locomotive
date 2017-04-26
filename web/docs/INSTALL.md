# Dependencies

```
pip install flask
pip install mongoengine
pip install flask_mongoengine
pip install celery==3.1.25    # 4+ does not support Windows?
pip install redis
```

You will also need to:

* Create a shared directory between the web application and the VM template
* Install mongodb (on your host)
* Install redis (on your host)

Create a file `config.yaml` in the same directory as `web.py`.

```
WEBAPP_IP: 
  "N.N.N.N"
MONGO_IP: 
  "N.N.N.N"
REDIS_IP: 
  "N.N.N.N"
PATH_SHARED: # Shared directory from the web application's perspective
  "/path/to/shared/folder/"
ANSIBLE_START_VM: # See the Ansible guidelines
   "path/to/create_vms.yaml"
ANSIBLE_STOP_VM:
    "path/to/stop_vms.yaml"

```

Execute `python web.py` and the application should be running.
