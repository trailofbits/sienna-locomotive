# Installation Instructions

SL2 requires a PC running the latest version of Windows 10. For testing purposes, you can use the free Windows 10 virtual machines from Microsoft. [Available here](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)

### Step 1: Disable Windows Error Reporting
1. Run `regedit`
2. Navigate to `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting` 
3. Create a new DWORD called "Disabled" and set the value to 1

### Step 2: Run the Installer
1. Right-click on `install.ps1` and click "Run with Powershell"
2. If you do not have Python 3.7+ installed, the script will prompt you to install it.
Be sure to select "Add Python 3.7 to PATH" 

### Step 3:
Restart your computer to apply the registry changes

### Step 4:
Double-click the "SL2 GUI" icon on the desktop
