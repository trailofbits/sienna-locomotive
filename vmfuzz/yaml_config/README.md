Configuration
=====================================

The user and system configurations are based on yaml files.

System configuration
=====================

```yaml
# Mandatory information
path_autoit_bin:
  # path to autoit executable
path_autoit_lib:
  # path to the autoit libraries
path_autoit_working_dir:
  # path used to create tmp files for the autoit lib system
path_windbg_dir:
  # path to windbg binaries directory
fuzzers:
  # list of available fuzzers

# Radamsa information
path_radamsa_bin:
  # path to radamsa
radamsa_number_files_to_create:
  # number of files create at each radamsa round
path_radamsa_working_dir:
  # path to the radamsa working directory

# Winafl information
path_winafl:
  # path to the winafl directory
path_dynamorio:
 # path to dynamorio
path_winafl_working_dir:
 # path to the winafl working directory
winafl_default_timeout:
 # used by winafl if no running time is provided
winafl_last_path_timeout:
 # timeout in minutes
winafl_fuzzing_iteration:
 # number of iteration before stop and running again the binary
path_autoit_stop_winafl:
 # autoit script used to close winafl windows (in case of errors)
path_windbg_script:
 # path to the offset computing system
```

User configuration
==================

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
- ``path_autoit_script` s needed

If `using_autoit` is `false`:
-  `auto_close` and `runnint_time` are needed


