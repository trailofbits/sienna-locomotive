Communication from vmfuzz to the webapp
======================================

**Getting the status of the run**

Request (get):

`HTTP://<ip>:500/_get_status/<run_id>`

Response:

`{"status": "THE_STATUS"}`

**Sending the stats of the run**

Request (post):

`HTTP://<ip>:500/_set_stats/<run_id>/<worker_id>`

Post: See [Stats](Database.md#stats)

**Sending the targets of the program**

Request (post):

`HTTP://<ip>:500/_set_targets/<program_id>` 

Post: See [Targets](Database.md#targets)

**Sending the classification (!exploitable) of a crash**

Request (post):

`HTTP://<ip>:500/_set_classification/<program_id>` 

Post: 

```python
{
    'crash_file': 'crash_file_name',
    'classificaiton': 'EXPLOITABLE'
}

```




Stats
=====
For winafl:

```python
{
        'fuzzers': "winafl",
        'target': target, # see target description
        'stats': {'unix_time': unix_time,
                  'cycles_done': cycles_done,
                  'cur_path': cur_path,
                  'paths_total': paths_total,
                  'pending_total': pending_total,
                  'pending_favs': pending_favs,
                  'map_size': map_size,
                  'unique_crashes': unique_crashes,
                  'unique_hangs': unique_hangs,
                  'max_depth': max_depth,
                  'execs_per_sec': execs_per_sec
                 }
}
```

For radamsa:

```python
{
        'fuzzers': "radamsa",
        'stats': {'unix_time': unix_time,
                  'cycles_done': cycles_done,
                  'runs_total': runs_total,
                  'number_crashes': number_crashes,
                 }
}
```

Targets
=======

Example of `target`:
```python
{
    'cov_modules':['mod_name1', 'mod_name2'],
    'module': 'mod_name1',
    'offset': '0x414141',

## Optional fields
    'number_path_recon': 0,
    'execs_sec_recon': 0
        
}
```

`targets` is a list of `target`:
```python

{ 
    'targets': [target0, target1, ..]
}
```
