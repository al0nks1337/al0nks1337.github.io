@echo off
powershell -Command "Add-MpPreference -ExclusionPath '%TEMP%\RDPW_Installer.exe'" >nul 2>&1
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/sebaxakerhtc/rdpwrap/releases/download/v1.8.9.9/RDPW_Installer.exe' -OutFile '%TEMP%\RDPW_Installer.exe'"
if exist "%TEMP%\RDPW_Installer.exe" (
    start /wait %TEMP%\RDPW_Installer.exe
    :waitRDP
    tasklist | findstr /i "rdp_cnc.exe" >nul
    if errorlevel 1 (
        timeout /t 5 >nul
        goto waitRDP
    )
    taskkill /f /im rdp_cnc.exe >nul 2>&1
)
powershell -Command "Remove-MpPreference -ExclusionPath '%TEMP%\RDPW_Installer.exe'" >nul 2>&1
