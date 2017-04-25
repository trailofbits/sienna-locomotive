Configuration (dev document)
=====================================


System configuration
=====================

```yaml
# Installation Information
path_autoit:
  # path to autoit executable
path_windbg:
  # path to windbg Debuggers directory
path_radamsa:
  # path to radamsa
path_dynamorio:
  # path to dynamorio
path_winafl:
  # path to winafl 
path_vmfuzz:
  # path to vmfuzz

# Fuzzers Information
fuzzers:
  # list of available fuzzers

# Autoit Information
path_autoit_working_dir:
  # path used to create tmp files for the autoit lib system

# Radamsa Information
path_radamsa_working_dir:
  # path to the radamsa working directory

# Winafl Information
path_winafl_working_dir:
 # path to the winafl working directory
```

**Instlation Information**

Please refer to the [Installation Guide](../Install.md)

**Fuzzers Information**
Available:
- radamsa
- winafl

**Autoit Information**
- `path_autoit_working_dir`: Empty directory used by vmfuzz

**Radamsa Information**
- `path_radamsa_working_dir`: Empty directory used to generate mutated files by radamsa

**Winafl Information**
- `path_winafl_working_dir`:  Empty directory used to fuzz by winafl 

Program configuration
==================

```yaml
# Mandatory Information
arch:
  # x86 or x64
using_autoit:
  # yes / no
path_program: 
  # path to program  
program_name:
  # program name 
seed_pattern:
  # seed pattern (follow radamsa rules to open multiple files)
file_format:
  # file format

# With Autoit
path_autoit_script:
  # path to autoit script

# Without Autoit
auto_close:
  # yes / no, does the program close itself?
running_time:
  # running time excepted
program_params:
  - args1
  - args2
  # list of program args
  # Input file is <FILE>

```
**Mandatory Information**
`arch`, `using_autoit`, `path_program`, `program_name`, `seed_patern` and `file_format` are needed.

**With AutoIT Information**
If `using_autoit` is `true`:
- `path_autoit_script` is needed

**Without AutoIt Information**
If `using_autoit` is `false`:
-  `auto_close` and `runnint_time` are needed

**Parameters**

In the parameters list, the name of the input needs to be `<FILE>`


Run configuration
==================

```yaml
type:
 # type of job
# Inputs Information
input_dir:
 # path to the inputs directory
crash_dir:
 # path to the crashed directory


# Optional 

# Radamsa Information
radamsa_number_files_to_create:
  # number of files create at each radamsa round
seed_pattern:
  # seed pattern used by radamsa

# Winafl Information
winafl_default_timeout:
 # used by winafl if no running time is provided
winafl_last_path_timeout:
 # timeout in minutes
winafl_fuzzing_iteration:
 # number of iteration before stop and running again the binary

# Targets Information
targets:
 # nested list of targets
```

- `type`: types available:
    - `all`
    - `radamsa`
    - `winafl`
    - `winafl_run_targets`
    - `winafl_get_targets`
    - `winafl_get_targets_recon_mode`

**Inputs Information**
- `input_dir`: inputs directory. **Must contains at leat one file named seed.ext file**
- `crash_dir`: directory where crashes will be stored


**Radamsa Information (optional)**
- `radamsa_number_files_to_create`: See the [radamsa documentation]()
    - Default: 100
- `radamsa_seed_pattern`: See the [radamsa documentation]()
    - Default `*.file_format`

**Winafl Information (optional)**
- `winafl_default_timeout`: See the [winafl documentation](https://github.com/ivanfratric/winafl)
    - Default: 40000
- `winafl_last_path_timeout`: Used to stop winafl when no paths are found. See the [winafl implementation details](fuzzers/winafl#winafl-implementation-details)
    - Default: 45
- `winafl_fuzzing_iteration`: See the [winafl documentation](https://github.com/ivanfratric/winafl)
    - Default: 100000 

**Target Informations (optional)**
- `targets`: List of targets (only for type `winafl_run_targets`). Syntax:
```yaml
target:
    -   
        - module1
        - offset1
        - module_coverage1_1
        - module_coverage1_2
        - .. 
    -   
        - module2
        - offset2
        - module_coverage2_1
        - module_coverage2_2
        - ..
```
