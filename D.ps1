Clear-Host
$msiPath = "$env:TEMP\ZeroTierOne.msi"
Invoke-WebRequest -Uri 'https://download.zerotier.com/dist/ZeroTier%20One.msi' -OutFile $msiPath -UseBasicParsing
if ((Test-Path $msiPath) -and ((Get-Item $msiPath).Length -gt 100000)) {
    Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /qn" -Wait
    Remove-Item $msiPath -Force

    $shortcut = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\ZeroTier.lnk"
    if (Test-Path $shortcut) {
        Remove-Item $shortcut -Force
    }

    $uiPath = "C:\Program Files (x86)\ZeroTier\One\zerotier_desktop_ui.exe"
    if (Test-Path $uiPath) {
        Start-Process $uiPath
    }

    sc.exe failure ZeroTierOne reset= 0 actions= restart/5000/restart/5000/restart/5000
    sc.exe config ZeroTierOne start= auto
} else {
    if (Test-Path $msiPath) { Remove-Item $msiPath -Force }
}
Exit
