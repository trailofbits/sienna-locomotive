# Dependencies

```
pip install flask
pip install mongoengine
pip install flask_mongoengine
pip install celery==3.1.25    # 4+ does not support Windows?
pip install redis
```

You will also need to:

* Create a shared directory
* Install mongodb (on your host)
* Install redis (on your host)

Configure the Mongo and Celery in `alternative_web.py` under the `INITIALIZATION` section. 