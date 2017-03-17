Usage
=============
**Minimal usage**


vmfuzz can be launched as follow:

```python
import vmfuzz
vmfuzz.main("config.yaml", "system.yaml", 0)
```
- `"config.yaml"`: the [user configuration](yaml_config/README.md#user-configuration) file
- `"system.yaml"`: the [system configuration](yaml_config/README.md#system-configuration) file
- `0` is the logging level: 0 debug 1 info, 2 warning, 3 error

`vmfuzz.log` contains the log.

**Radamsa usage**

```python
import vmfuzz
vmfuzz.fuzz_radamsa("config.yaml", "system.yaml", 0)
```
- `"config.yaml"`: the [user configuration](yaml_config/README.md#user-configuration) file
- `"system.yaml"`: the [system configuration](yaml_config/README.md#system-configuration) file
- `0` is the logging level: 0 debug 1 info, 2 warning, 3 error

`vmfuzz.log` contains the log.

**Winafl basic usage**

```python
import vmfuzz
vmfuzz.fuzz_winafl("config.yaml", "system.yaml", 0)
```
- `"config.yaml"`: the [user configuration](yaml_config/README.md#user-configuration) file
- `"system.yaml"`: the [system configuration](yaml_config/README.md#system-configuration) file
- `0` is the logging level: 0 debug 1 info, 2 warning, 3 error

`vmfuzz.log` contains the log.

**Winafl on a specific target**

```python
import vmfuzz
vmfuzz.fuzz_winafl_one_target("config.yaml", "system.yaml", 0, offset, module)
```
- `"config.yaml"`: the [user configuration](yaml_config/README.md#user-configuration) file
- `"system.yaml"`: the [system configuration](yaml_config/README.md#system-configuration) file
- `0` is the logging level: 0 debug 1 info, 2 warning, 3 error
- `offset`: the offset (int)
- `module`: the module (string)

`vmfuzz.log` contains the log.

**Winafl on a set of targets**

```python
import vmfuzz
vmfuzz.fuzz_winafl_one_target("config.yaml", "system.yaml", 0, target_file)
```
- `"config.yaml"`: the [user configuration](yaml_config/README.md#user-configuration) file
- `"system.yaml"`: the [system configuration](yaml_config/README.md#system-configuration) file
- `0` is the logging level: 0 debug 1 info, 2 warning, 3 error
- `target_file`: the file containing the targets

`vmfuzz.log` contains the log.

Example of target_file:
```
0x8cbe0;libclamav.dll
0x1000;clamscan.exe
```

**Winafl recon mode**
```python
import vmfuzz
vmfuzz.winafl_launch_recon("config.yaml", "system.yaml", 0, target_file)
```
- `"config.yaml"`: the [user configuration](yaml_config/README.md#user-configuration) file
- `"system.yaml"`: the [system configuration](yaml_config/README.md#system-configuration) file
- `0` is the logging level: 0 debug 1 info, 2 warning, 3 error
- `target_file`: the file where the targets will be stored

Example of target_file:
```
0x8cbe0;libclamav.dll
0x1000;clamscan.exe
```

TODO: documentation of recon mode

**Other examples**

Other examples are available in [tests](tests)



