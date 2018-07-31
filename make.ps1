#Set-PSDebug -Trace 1
$cwd=(Get-Item -Path ".\").FullName


Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}


Function InstallDependencies {
    $deps = @("msgpack", "pyqt5")
    foreach ( $dep in $deps ) {
        "Installing $dep"
        pip install "${dep}"
    }
}

Function DynamioRioInstall {

    $dynamorioDir = "dynamorio"
    $dynamorioBase = "DynamoRIO-Windows-7.0.17721-0"

    If ( Test-Path $dynamorioDir ) {
        $dynamorioDir + " already exists "
        return
    } 

    $url="https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-7.0.17721/${dynamorioBase}.zip"

    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'
    $client = New-Object System.Net.WebClient

    $zip = $cwd + "\dr.zip"
    "Downloading " + $url 
    $client.DownloadFile($url, $zip)
    "Unzipping " + $zip
    Unzip $zip $cwd
    mv $dynamorioBase $dynamorioDir
}



Function Build {
    Push-Location
    InstallDependencies
    DynamioRioInstall

    #if not exist "build" mkdir build
    New-Item -ItemType Directory -Force -Path build
    cd build
    $dynamorioCmake="${cwd}\dynamorio\cmake"
    cmake -G"Visual Studio 15 Win64" "-DDynamoRIO_DIR=${dynamorioCmake}" ..
    cmake --build .
    Pop-Location
}


Function SafeDelete {
    param( [string]$path )
 
    if ( Test-Path "$path" ) {
        "Deleting ${path}"
        Remove-Item $path -Force -Recurse
    } 
}

Function Reconfig {
    taskkill.exe /IM test_application.exe /F
    taskkill.exe /IM server.exe /F
    SafeDelete "$env:APPDATA\Trail of Bits\fuzzkit"
}

Function Test {
    python harness.py  -v -r10  -t build\corpus\test_application\Debug\test_application -a 8 
    #python harness.py  -v -r10 -e FUZZER -t build\corpus\test_application\Debug\test_application -a 8 
    #dynamorio\bin64\drrun.exe -pidfile pidfile -verbose -persist -c build\triage_dynamorio\Debug\tracer.dll -t "C:\Users\IEUser\AppData\Roaming\Trail of Bits\fuzzkit\targets\TEST_APPLICATION_acfa4ea300cade2f47bc7f8ab4502453a7fe774b\targets.json" -r d3e03566-8db8-4c94-bb69-353008abae49 -- build\corpus\test_application\Debug\test_application.exe "0 -f"
}


Function Clean {
    Reconfig
    SafeDelete "build"
    "It's clean!"
    
}

Function Dep {
    SafeDelete "dr.zip"
    SafeDelete "dynamorio"
}

Function Help {
    @'
Usage: make1.ps [clean|dep|reconfig|help]

make1.ps without any options will build


clean
    Cleans build directory and configuration (reconfigs)

dep
    Rebuild dependencies

reconfig
    Deletes fuzzkit directory with run configuration

help
    This info    
'@
}


function Regress {
    python .\regress.py    
}

$cmd = $args[0]

switch( $cmd ) {
    "clean"             { Clean }
    "dep"               { Dep }
    "reconfig"          { Reconfig }
    "regress"           { Regress }
    "help"              { Help }
    "test"              { Test }
    default             { Build }   
}
