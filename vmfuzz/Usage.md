Usage
=============
**Minimal usage**


vmfuzz can be launched as follow:

```python
import vmfuzz
vmfuzz.main("system.yaml", "program.yaml", "run.yaml", 0)
```
- `"system.yaml"`: the [system configuration](Configuration.md#system-configuration) file
- `"program.yaml"`: the [program configuration](Configuration.md#program-configuration) file
- `"run.yaml"`: the [run configuration](Configuration.md#run-configuration) file
- `0` is the logging level: 0 debug 1 info, 2 warning, 3 error

`vmfuzz.log` contains the log.


To call vmfuzz directly with python dictionaries:

```python
import vmfuzz
vmfuzz.main(conf_system, conf_program, run_program)
```

See [the webapp testcase](tests/test_webapp.py) for an example.

**Other examples**

Other examples are available in [tests](tests)



