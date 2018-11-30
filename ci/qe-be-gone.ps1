# qe-be-gone: Disable QuickEdit on all (future) consoles

# QuickEdit interferes with program execution, and the Travis
# Windows instances are currently too opaque to determine whether or not
# QuickEdit is the source of some of the hangs I've seen. So, we
# just disable it and forget about it entirely.

$conPath = "HKCU:\Console"

if (!(Test-Path $conPath)) {
    New-Item -Path $conPath -Force | Out-Null
}

New-ItemProperty -Path $conPath -Name "QuickEdit" -Value 0 -PropertyType DWORD -Force | Out-Null
