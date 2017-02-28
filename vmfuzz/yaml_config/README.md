Configuration
=====================================


The user and system configurations are based on yaml files.

**System config:**
```yaml
path_radamsa_bin:
  # path to radamsa
path_autoit_bin:
  # path to autoit executable
path_wingdb_dir:
  # path to wingdb binaries directory
```
`path_radamsa_bin` and `path_wingdb_dir` are required.

**User configuration:**
```yaml
using_autoit:
  # yes / no
path_autoit_script:
  # path to autoit script
path_program: 
  # path to program  
program_name:
  # program name 
program_params:
  - args1
  - args2
  # list of program args
auto_close:
  # yes / no, does the program close itself?
running_time:
  # running time excepted
seed_pattern:
  # seed pattern (follow radamsa rules to open multiple files)
file_format:
  # file format
```

`using_autoit`, `path_program`, `program_name`, `seed_patern` and `file_format` are needed.

If `using_autoit` is `true`:
- `path_auotit` and `path_autoit_script` are needed

If `using_autoit` is `false`:
-  `auto_close` is needed
	- if `auto_close` is `false`, `running_time` is needed


