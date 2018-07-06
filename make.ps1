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
    $dynamorioBase = "DynamoRIO-Windows-7.0.0-RC1"

    If ( Test-Path $dynamorioDir ) {
        $dynamorioDir + " already exists "
        return
    } 

    $url="https://github.com/DynamoRIO/dynamorio/releases/download/release_7_0_0_rc1/${dynamorioBase}.zip"
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