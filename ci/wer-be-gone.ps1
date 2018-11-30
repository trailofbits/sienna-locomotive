# wer-be-gone: Disable Windows Error Reporting

# WER interferes with SL2, by design. The tests will refuse
# to run with it enabled.

$werPath = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"

if (!(Test-Path $werPath)) {
    New-Item -Path $werPath -Force | Out-Null
}

New-ItemProperty -Path $werPath -Name "Disabled" -Value 1 -PropertyType DWORD -Force | Out-Null
