$ErrorActionPreference = "Stop"
$cwd=(Get-Item -Path ".\").FullName

Function InstallPython{
    $url="https://www.python.org/ftp/python/3.7.0/python-3.7.0-amd64-webinstall.exe"

    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'
    $client = New-Object System.Net.WebClient

    "Downloading Python from " + $url
    $exe = "$cwd\python_install.exe"
    $client.DownloadFile($url, $exe)

   & .\python_install.exe

    "Python has finished installing. Please restart Powershell and run install.ps1 again."

    & cmd /c pause
    exit

}

Function GetPythonVersion {
    python -c "import sys; exit(0 if (sys.version_info.major == 3 and sys.version_info.minor >= 7) else 1)"
    if ($lastExitCode -ne 0){
        Throw "``python`` points to Python interpreter below version 3.7.0"
    }
}

try { GetPythonVersion }
catch {
    "Could not find Python 3.7+! Attempting to install 3.7.0 now..."
    InstallPython
}

try { python -m pip install setuptools }
catch {
    "Failed to install setuptools! Try running ``pip install setuptools`` in Powershell"

    & cmd /c pause
    exit
}

try { python -m pip install -r requirements.txt }
catch {
    "Failed to install Python dependencies!"

    & cmd /c pause
    exit
}

Function CheckForRegistry{
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "Disabled"
}

"Checking to see if WER is disabled"
try { CheckForRegistry }
catch {
    "You have not disabled Windows Error Reporting! This may interfere with the SL2 Unit Tests. Please follow the instructions in the README to disable it and run install.ps1 again."
    & cmd /c pause
    exit
}

"Installing Dependencies and creating scripts"
python setup.py install --install-scripts "$cwd\Scripts"

"Writing Shortcuts"
$TargetFile = "`"$cwd\Scripts\sl2.exe`""
$ShortcutFile = "$env:USERPROFILE\Desktop\SL2 GUI.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
"Writing Shortcut for $TargetFile"
$Shortcut.TargetPath = $TargetFile
$Shortcut.Arguments = ""
$Shortcut.WorkingDirectory = $cwd
$Shortcut.IconLocation = "$cwd\icon.ico"
$Shortcut.Description = "Sienna Locomotive 2 Graphical Fuzzing Interface"

$Shortcut.Save()

$TargetFile = "`"$env:APPDATA\Trail of Bits\fuzzkit\`""
$ShortcutFile = "$env:USERPROFILE\Desktop\SL2 Working Files.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
"Writing Shortcut for $TargetFile"
$Shortcut.TargetPath = "explorer.exe"
$Shortcut.Arguments = $TargetFile
$Shortcut.Description = "SL2 Run Files"

$Shortcut.Save()

"Running Tests"
.\Scripts\sl2-test.exe

"Sienna Locomotive 2 has been succesfully installed. You can now run the GUI via the shortcut on the desktop, or by typing `sl2` into Powershell."

& cmd /c pause
exit