VMFuzz
=====================================

Tested on Win 7, fuzzing with radamsa.

Programs tested:
- Sumatra pdf (v.3.2.1): http://www.sumatrapdfreader.org/download-free-pdf-viewer.html
- Easy RM to MP3 convertor (v2.3.7, with buffer overflow from: https://www.exploit-db.com/exploits/9177/)
- Vlc (v2.2.1, with buffer overflow from: https://www.exploit-db.com/exploits/38485/): https://www.videolan.org/vlc/releases/2.2.1.html


**Windows Instalation**
------------------------
- Python: https://www.python.org/downloads/release/python-2713/
- Python yaml: http://pyyaml.org/download/pyyaml/PyYAML-3.12.win32-py2.7.exe
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

- Wingdb: https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
- Visual C++ Redistributable for Visual Studio 2012 https://www.microsoft.com/en-us/download/details.aspx?id=30679
- !exploitable: https://msecdbg.codeplex.com/
   - copy and paste MSEC.dll in `winext` of the wingdb directory

- pykd (TODO doc)

**Usage**
---------

```python
import vmfuzz
vmfuzz.main("config.yaml","system".yaml,"path_to_working_dir",0)
```
- `"config.yaml"`: the user configuration file
- `"system.yaml"`: the system configuration file
- `"path_to_working_dir"`: working directory for inputs files (seeds and generated inputs)
- `0` is the logging level: 0 debug 1 info, 2 warning, 3 error

Examples are available in `test_sumatra.py` / `test_easymp3.py` / `test_vlc.py`.

`vmfuzz.log` contains the log.

If a crash is detected, a file `crash-N` is created in the working directory.


**Limitations**
----------------

- Architecture only works with "radamsa-like" fuzzers and winafl;
- Only fuzz one file;
- Need to be careful when writting autoit script.

