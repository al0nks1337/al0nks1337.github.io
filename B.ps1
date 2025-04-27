Clear-Host
Start-Process -FilePath "changepk.exe" -ArgumentList "/ProductKey NPPR9-FWDCX-D2C8J-H872K-2YT43" -NoNewWindow -Wait
cscript.exe //nologo slmgr.vbs /ipk CPWHC-NT2C7-VYW78-DHDB2-PG3GK *> $null
$temp = [System.IO.Path]::GetTempPath()
$masPath = Join-Path -Path $temp -ChildPath "MAS_AIO.cmd"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/refs/heads/master/MAS/All-In-One-Version-KL/MAS_AIO.cmd" -OutFile $masPath
Start-Process -FilePath $masPath -ArgumentList "/HWID" -Wait
Remove-Item -Path $masPath -Force
Exit
