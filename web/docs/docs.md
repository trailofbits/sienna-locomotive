# YAML Configuration

## System Configuration

The system configuration specifies the paths of required files and folder used in fuzzing. This should be created once for the base VM that is to be cloned when fuzzing. 

```yaml
  # name of system config
  name:
    System Name
  # path to autoit executable
  path_autoit:
    C:\Program Files (x86)\AutoIt3\
  # path to windbg Debuggers directory
  path_windbg:
    C:\Program Files (x86)\Windows Kits\10\Debuggers\
  # path to radamsa
  path_radamsa:
    C:\cigwin64\bin\
  # path to dynamorio
  path_dynamorio:
    C:\Users\uname\fuzzing\dynamorio\
  # path to winafl 
  path_winafl:
    C:\Users\uname\fuzzing\winafl-master\
  # path to vmfuzz
  path_vmfuzz:
    C:\Users\uname\fuzzing\vmfuzz\
  # list of available fuzzers
  fuzzers:
    - winafl
    - radamsa
  # path used to create tmp files for the autoit lib system
  path_autoit_working_dir:
    C:\Users\uname\fuzzing\working\autoit\
  # path to the radamsa working directory
  path_radamsa_working_dir:
    C:\Users\uname\fuzzing\working\radamsa\
  # path to the winafl working directory
  path_winafl_working_dir:
    C:\Users\uname\fuzzing\working\winafl\
```

## Program Configuration

The program configuration tells the fuzzer how to execute the program. There are some options that are required for command line applications, and some that are required for GUI applications (`using_autoit: yes`). 

```yaml
  # name of program config
  name:
    Program Name
  # x86 or x64
  arch:
    x64
  # Fuzzing a GUI with AutoIT (yes / no)
  using_autoit:
    no
  # path to program  
  path_program: 
    C:\Program Files\program\
  # binary name 
  program_name:
    program.exe
  # extension of file being fuzzed
  file_format:
    .txt
  
  ### Command Line Specific (using_autoit no)

  # Does the program close itself (yes / no)
  auto_close:
    yes
  # running time excepted
  running_time:
    2
  # arguments to the program
  program_params:
    - -o
    - <FILE> # replaced with the mutated file
  
  ### AutoIt Specific (using_autoit yes)

  # path to autoit script
  path_autoit_script:
    C:\Users\uname\fuzzing\scripts\


 ### Ansible 

 # base name of template vm
 #  Note: in VirtualBox you must clone the VM
 #  with names 
 #  <vmtemplate>_0, <vmtemplate>_1, ..., <vmtemplate>_n
 #  where n is the number_workers (in run config) minus 1
 vmtemplate:
    Name of VM
```

## Run Configuration

The program configuration can be executed many times as `runs`. Most simply, you only need to provide the name of the run. You can optionally provide an amount of time to fuzz for and some parameters to tweak WinAFL and Radamsa.

```yaml
  # name of run config
  name:
    Run Name
  
  ### Optional 

  # time (minutes) to fuzz for
  fuzz_time:
    1440 # 24h
  number_workers:
    2    # number of VMs that are running or are to be started with Ansible
  
  ### Optional Winafl Configuration

  # timeout before changing targets (minutes)
  winafl_last_path_timeout:
    45
  # number of iterations before restarting the process
  winafl_fuzzing_iteration:
    100000  
  # nested list of targets
  targets:
    -
      - module.dll    # module of target function
      - offset        # offset of target function
      - module.dll    # coverage targets
      - program.exe
  
  ### Optional Radamsa Configuration

  # number of files create at each radamsa round
  radamsa_number_files_to_create:
    100
  # seed pattern used by radamsa
  seed_pattern:
    "*.txt"
```