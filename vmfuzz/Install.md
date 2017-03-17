Windows Instalation
===================

Please note that several path defined here are used in the configuration of vmfuzz ([Configuration Guide](yaml_config/))


**Python**
--------
- Python: https://www.python.org/downloads/release/python-2713/ 
    - On 32 bits VM, install only Python 32 bits
    - On 64 bits VM, install both Python 32 and 64 bits (on separate directory)
    - Customize Python -> Select "Add Python.exe to Path"
- Python yaml:
    - http://pyyaml.org/download/pyyaml/PyYAML-3.12.win32-py2.7.exe (32 bits VM)
    - Or http://pyyaml.org/download/pyyaml/PyYAML-3.12.win-amd64-py2.7.exe (64 bits VM)

**Autoit**
- Autoit (https://www.autoitscript.com/site/autoit/downloads/):
    - direct link: https://www.autoitscript.com/cgi-bin/getfile.pl?autoit3/autoit-v3-setup.exe

> **Note**: The path to AutoIt3.exe is asked during the vmfuzz configuration (`path_autoit_bin`).

**windbg**
- Windbg: https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
- You may have to install some Windows updates before installing windbg (according to you windows version). Follow the windbg installer to know which one
- You only need to install the "Debugging tools for Windows"
- The wingdb installation directory looks like `path\Windows Kits\10\Debuggers`, where two folders `x86` and `x64` are presents in `Debuggers`
- !exploitable: https://msecdbg.codeplex.com/
   - direct link: https://msecdbg.codeplex.com/downloads/get/671417
   - from the .zip copy x86/Release/MSEC.dll to `x86\winext` on the windbg installation directory 
   - from the .zip copy x64/Release/MSEC.dll to `x64\winext` on the windbg installation directory 
   - Install the Visual C++ Redistributable for Visual Studio 2012 https://www.microsoft.com/en-us/download/details.aspx?id=30679

- pykd: https://pykd.codeplex.com/releases/view/630923 
    - pykd-0.3.2.1-cp27-win32.zip for x84 applications
    - pykd-0.3.2.1-cp27-win-amd64.zip for x64 applications
    - copy and past all the *.dll and pykd.pyd in `winext` of the windbg installation directory
        - the x86 version in `x86\winext`
        - the x64 version in `x64\winext`


> **Note**: The path to the `Debuggers` folder is asked during the vmfuzz configuration (`path_windbg_dir`).

**Radamsa**

- Cygwin: https://cygwin.com/install.html. 
    - direct link: https://cygwin.com/setup-x86.exe (32bits), https://cygwin.com/setup-x86_64.exe (64bits) 
- Python package needed (asked during the installation of cygwin):
     - make
     - gcc-core
     - git
     - wget

- Radamsa: in cygwin terminal:
```
git clone https://github.com/aoh/radamsa.git
cd radamsa
make
make install 
```
- `radamsa.exe` is present in `path\cygwin\home\monty\radamsa\bin`

> **Note**: The path to the radamsa.exe is asked during the vmfuzz configuration (`path_radamsa_bin`).


**Winafl**
- DynamoRIO: https://github.com/DynamoRIO/dynamorio/wiki/Downloads (version 7.0.0.rc1)
    - direct link: https://github.com/DynamoRIO/dynamorio/releases/download/release_7_0_0_rc1/DynamoRIO-Windows-7.0.0-RC1.zip
- Do not need to be complied or installed, binaries are present in `bin32` and `bin64` of the zip file
- http://www.microsoft.com/download/en/details.aspx?displaylang=en&id=8279
     - Only Microsoft Visual C++ 2010 required 
> **Note**: The path to dynamorio is asked during the vmfuzz configuration (`path_dynamorio`).

- Winafl: https://github.com/ivanfratric/winafl
    - Direct link: https://github.com/ivanfratric/winafl/archive/master.zip  
- Do not need to be complied or installed, Binaries are present in `bin32` and `bin64` of the zip file
 
> **Note**: The path to winafl is asked during the vmfuzz configuration (`path_winafl`).


> **Note devs**: please ensure that winafl was built with the right version of dynamorio

**VMfuzz**
- Copy vmfuzz into the VM

> **Note**: The path to vmfuzz is asked during the vmfuzz configuration (`path_vmfuzz`).


**Microsoft Windows**

Please remove the automatic updates of windows (otherwise the system could restart during fuzzing)

TODO: check how to keep the update but do not permit automatic restart

