#Set-PSDebug -Trace 1
$cwd=(Get-Item -Path ".\").FullName


Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}


Function InstallDependencies {
    $deps = @()
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
    SafeDelete "$env:APPDATA\Trail of Bits\fuzzkit"
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


$cmd = $args[0]

if(         $cmd -eq "clean" ) {
    Clean
} ElseIf(   $cmd -eq "dep" ) {
    Dep
} ElseIf(   $cmd -eq "reconfig" ) {
    Reconfig
} ElseIf(   $cmd -eq "help" ) {
    Help
} else {
    Build
}