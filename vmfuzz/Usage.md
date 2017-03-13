Usage
=============
**Minimal usage**

A seed file named "seed.extension" in the directory `in_program_name` from the path `path_winafl_working_dir` ([system configuration](yaml_config/README.md#system-configuration)) have to be present (see the [winafl documentation](fuzzers/winafl)).

Then, vmfuzz can be launched as follow:

```python
import vmfuzz
vmfuzz.main("config.yaml", "system.yaml", 0)
```

- `"config.yaml"`: the [user configuration](yaml_config/README.md#user-configuration) file
- `"system.yaml"`: the [system configuration](yaml_config/README.md#system-configuration) file
- `0` is the logging level: 0 debug 1 info, 2 warning, 3 error

Examples are available in [tests](tests)


`vmfuzz.log` contains the log.

