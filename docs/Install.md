# Creation of the VM Template


The system needs one *template VM* per target program.

- Follow the [system VM installation](#system-vm-installation) to create a *system VM*.
    - A *system VM* contains all the vmfuzz dependencies
- Follow the [template VM installation](#template-vm-installation) to create a *template VM*
    - A *template VM* is a *system VM* containing the target program
- One *system VM* can be used to create multiple *template VM*.

## System VM Installation

All the installers are present in the `VMfuzz_install.zip` file (SHA-256: 664118fc9a06d5da54cd64b2caedaf0b5a862a92233e8d8c0ccf71b8a28945a7, tested on Windows 8.1). 

The virtual machine needs an Internet connection to install the dependencies.

**Python**



- [Python](https://www.python.org/downloads/release/python-2713/)
    - 32 bits installer: `VMfuzz_install/python/32/python-2.7.13.msi` ([original link](https://www.python.org/ftp/python/2.7.13/python-2.7.13.amd64.msi))
    - 64 bits installer: `VMfuzz_install/python/64/python-2.7.13.amd64.msi` ([original link](https://www.python.org/ftp/python/2.7.13/python-2.7.13.amd64.msi))
    - On 32 bits VM, install only Python 32 bits  
    - On 64 bits VM, install Python 32 and then Python 64 bits (on separate directory)
    - During the instalation, selection 'Customize Python' -> And select "Add Python.exe to Path"
- Python yaml:
    - 32 bits installer: `VMfuzz_install/python/32/PyYAML-3.12.win32-py2.7.exe` ([original link](http://pyyaml.org/download/pyyaml/PyYAML-3.12.win32-py2.7.exe))
    - 64 bits installer: `VMfuzz_install/python/64/PyYAML-3.12.win-amd64-py2.7.exe` ([original link](http://pyyaml.org/download/pyyaml/PyYAML-3.12.win32-py2.7.exe))
- Python request. In a Windows terminal:
```bash
pip install requests
```

**Autoit**


- [Autoit](https://www.autoitscript.com/): `VMfuzz_install/autoit/autoit-v3-setup.exe` ([original link](https://www.autoitscript.com/cgi-bin/getfile.pl?autoit3/autoit-v3-setup.exe))

> **Note**: The path to AutoIt3.exe is asked during the system configuration (`path_autoit`).

**windbg**
- Windbg: `VMfuzz_install/windbg/windsksetup.exe` ([original link](https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk))
    - You may have to install some Windows updates before installing windbg (according to you windows version). Follow the windbg installer to know which one
    - You only need to install the "Debugging tools for Windows"
    - The wingdb installation directory looks like `path\Windows Kits\10\Debuggers`, where two folders `x86` and `x64` are presents in `Debuggers`
- pykd ([original link](https://pykd.codeplex.com/releases/view/630923))
    - 32 bits: `VMfuzz_install/windbg/pykd_32`
    - 64 bits: `VMfuzz_install/windbg/pykd_64`
    - Copy all the *.dll and pykd.pyd in `winext` of the windbg installation directory
- [!exploitable](https://msecdbg.codeplex.com/): `VMfuzz_install/windbg/exploitable` ([original link](https://msecdbg.codeplex.com/downloads/get/671417))
   - Copy `x86/Release/MSEC.dll` to `x86\winext` of the windbg installation directory 
   - Copy `x64/Release/MSEC.dll` to `x64\winext` of the windbg installation directory 
- Visual C++ Redistributable for Visual Studio 2012 ([original link](https://www.microsoft.com/en-us/download/details.aspx?id=30679))
    - 32 bits installer: `VMfuzz_install/windbg/vcredist_x86_2012.exe`
    - 64 bits installer: `VMfuzz_install/windbg/vcredist_x64_2012.exe`
> **Note**: The path to the `Debuggers` folder is asked during the system configuration (`path_windbg`).

**Radamsa**

- [Cygwin](https://cygwin.com/install.html)
    - 32 bits installer: `VMfuzz_install/radamsa/cygwin/setup-x86.exe` ([original link](https://cygwin.com/setup-x86.exe))
    - 64 bits installer: `VMfuzz_install/radamsa/cygwin/setup-x86_64.exe`([original link](https://cygwin.com/setup-x86_64.exe))
    - Packages needed (asked during the installation of cygwin):
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
- `radamsa.exe` is present in `<path>\cygwin\home\<user>\radamsa\bin`

> **Note**: The path to the radamsa.exe is asked during the system configuration (`path_radamsa`).


**Winafl**
- [DynamoRIO](https://github.com/DynamoRIO/dynamorio): `VMfuzz_install/winafl/dynamorio` ([original link](https://github.com/DynamoRIO/dynamorio/releases/download/release_7_0_0_rc1/DynamoRIO-Windows-7.0.0-RC1.zip))
    - Copy the directory in the VM 

> **Note**: The path to dynamorio is asked during the system configuration (`path_dynamorio`).

- [Winafl](https://github.com/ivanfratric/winafl): `VMfuzz_install/winafl/winafl` ([original link](https://github.com/ivanfratric/winafl/archive/master.zip))
    - Copy the directory in the VM 

> **Note**: The path to winafl is asked during the system configuration (`path_winafl`).

> **Note devs**: please ensure that winafl was built with the right version of dynamorio


- Microsoft Visual C++ 2010 Redistributable Package  
    - 32 bits installer: `VMfuzz_install/winafl/vcredist_x86_2010.exe` ([original link](https://www.microsoft.com/en-ie/download/details.aspx?id=5555))
    - 64 bits installer: `VMfuzz_install/winafl/vcredist_x64_2010.exe`  ([original link](https://www.microsoft.com/en-US/Download/confirmation.aspx?id=14632))



**VMfuzz**

- Copy VMfuzz in the VM

> **Note**: The path to VMfuzz is asked during the system configuration (`path_vmfuzz`).


**VM Startup**

Create `startup.bat` in the `shell:startup` directory of Windows of the template as follows:
```batch
X: 
cd X:\path_to_sienna_locomotive\web
for /f "delims=[] tokens=2" %%a in ('ping -4 -n 1 %ComputerName% ^| findstr [') do set NetworkIP=%%a
set hostname=worker%RANDOM%@%NetworkIP%
celery -A web.celery worker -n %hostname% -f %hostname%.log

```

- ``X:`` is used if the `sienna_locomotive\web` directory is in not in the C: directory
- The `<hostname>` is composed of the IP address of the VM and a random number.
- A file `<hostnane>.log` is created (debuging purpose)


This script will launch vmfuzz at each startup.

A first start of the VM is needed to allow the launch of the script at the startup.



**Microsoft Windows Tuning**

- Disable the automatic updates of Windows:
    - Search "Windows Update Settings" in the windows starting menu.
    - Click "Choose how updates get installed".
    - Select "Never check for updates (not recommended)".
- Disable Windows Defender:
    - Search "gpedit.msc " in the windows starting menu.
    - Browse "Computer Configuration > Administrative Templates > Windows Components > Windows Defender"
    - Click "Turn off Windows Defender"
    - Select "Enabled", then "Apply" and "Ok"
- (Optional): Follow the [optimization advice](https://github.com/artemdinaburg/OptimizeVM).



## Template VM Installation

Create a *template VM* on top of a *system VM*.
- Install the target program and all its required dependencies in the virtual machine.
- If you need GUI interactions, follow the [AutoIT tutorial](AutoIT.md).


> **Note**: Information on the program installation are asked during the program configuration (see [the program configuration](../web/docs/docs.md#program-configuration))

