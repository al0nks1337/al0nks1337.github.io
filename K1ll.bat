@echo off
title  
echo Wscript.Sleep 1000 > "%TEMP%\1.vbs"
changepk.exe /ProductKey NPPR9-FWDCX-D2C8J-H872K-2YT43 >nul 2>&1
cscript //nologo "%TEMP%\1.vbs"
cscript //nologo slmgr.vbs /ipk CPWHC-NT2C7-VYW78-DHDB2-PG3GK >nul 2>&1
cscript //nologo "%TEMP%\1.vbs"
powershell -Command "$temp = [System.IO.Path]::GetTempPath(); Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/refs/heads/master/MAS/All-In-One-Version-KL/MAS_AIO.cmd' -OutFile ($temp + 'MAS_AIO.cmd')"
"%TEMP%\MAS_AIO.cmd" /HWID
del "%TEMP%\MAS_AIO.cmd"
del "%TEMP%\1.vbs"
