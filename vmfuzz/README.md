VMFuzz
=====================================

Tested on Win 7, fuzzing with radamsa.

Programs tested:
- Sumatra pdf (v.3.2.1)
- Easy (v2.3.7, with buffer overflow from: https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
- Vlc (v2.2.1, with buffer overflow from: https://www.exploit-db.com/exploits/38485/)


**Windows Instalation**
- Python: http://pyyaml.org/download/pyyaml/PyYAML-3.12.win32-py2.7.exe
- Autoit: https://www.autoitscript.com/site/autoit/downloads/
- Cygwin: https://cygwin.com/install.html. Python package needed:
     - make
     - gcc
     - git
     - wget

- Radamsa: in cygwin terminal:
```
git clone https://github.com/aoh/radamsa.git
cd radamsa
make
make install 
```

**Usage**

```python
import vmfuzz
vmfuzz.main("config.yaml","path_to_working_dir",0)
```
- `"config.yaml"`: the configuration file
- `"path_to_working_dir"`: working directory for inputs files (seeds and generated inputs)
- `0` is the logging level: 0 debug 1 info, 2 warning, 3 error

Examples are available in `test_sumatra.py` / `test_easymp3.py` / `test_vlc.py`.

`vmfuzz.log` contains the log.

If a crash is detected, a file `crash-N` is created in the working directory.

**Configuration**

The configuration is based on a yaml file.

```yaml
using_autoit:
  # yes / no
path_autoit:
  # path to autoit executable
path_autoit_script:
  # path to autoit script
path_program: 
  # path to program  
program_name:
  # program name 
auto_close:
  # yes / no, does the program close itself?
running_time:
  # running time excepted
path_radamsa:
  # path to radamsa
seed_pattern:
  # seed pattern (follow radamsa rules to open multiple files)
file_format:
  # file format
```

`using_autoit`, `path_radamsa`, `seed_patern` and `file_format` are needed.

If `using_autoit` is `true`:
- `path_auotit` and `path_autoit_script` are needed

If `using_autoit` is `false`:
- `path_program`, `program_name`, `auto_close` are needed
	- if `auto_close` is `false`, `running_time` is needed


**AutoIT script**

Examples are provided in the folder `auto_it_scripts`.

The script has to send "no error" to stdout if no crash is detected:
```
ConsoleWrite("no error")
```

Idea: build a library for autoit scripts; then the user only needs to call some functions in his script.

**Crash Detection**

If the application does not close itself:
- Check if the process is still running

If the application closes itself:
- Check the return value (not yet implemented)

Additional checks:
- Check if `WerFault.exe` is running
- ...


**Crash Analysis**

TODO

- !exploitable
- our taint analysis


**Limitations**

- Architecture only works with "radamsa-like" fuzzers;
- Only fuzz one file;
- Need to be careful when writting autoit script.

