VMFuzz
=====================================

Tested on Win 7, fuzzing with radamsa.

Programs tested:
- Sumatra pdf (v.3.2.1): http://www.sumatrapdfreader.org/download-free-pdf-viewer.html
- Easy RM to MP3 convertor (v2.3.7, with buffer overflow from: https://www.exploit-db.com/exploits/9177/)
- Vlc (v2.2.1, with buffer overflow from: https://www.exploit-db.com/exploits/38485/): https://www.videolan.org/vlc/releases/2.2.1.html
- WinSCP 
- 7zip

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
   - copy and paste MSEC.dll in `winext` of the windbg directory

- pykd (TODO doc)


**Other documentations**
-----------------------
- [Minimal usage](Usage.md)
- [How to configure the system](yaml_config/README.md)
- [How to create autoit script](autoit_lib/README.md)
- [Fuzzers available](fuzzers/README.md)
- [Particular behaviors details](Behavior.md)
- [Exploitatbility analysis](exploitability/README.md) (to be dev)
- [Modules tests](tests/README.md) 

**Limitations**
----------------

- Architecture only works with "radamsa-like" fuzzers and winafl;
- Only fuzz one file;
- Need to be careful when writting autoit script.

