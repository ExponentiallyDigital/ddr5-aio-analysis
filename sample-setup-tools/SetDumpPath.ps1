# SetDumpPath.ps1 - ensures dump dir exists, sets unique filename so dumps are retained
# run as a scheduled task at boot


# !!!!!!!!!!!!!
# !!!!!!!!!!!!! edit below line:
# !!!!!!!!!!!!!
$DumpRoot = "C:\CrashDumps"
	
# Ensure directory exists
if (!(Test-Path $DumpRoot)) {
    New-Item -ItemType Directory -Path $DumpRoot | Out-Null
}
	
# Generate unique filename
$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$DumpFile = "$DumpRoot\FullDump_$Timestamp.dmp"
	
# CrashControl registry path
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
	
# Ensure full dump mode
Set-ItemProperty -Path $RegPath -Name "CrashDumpEnabled" -Value 1
	
# Set dump filename
Set-ItemProperty -Path $RegPath -Name "DumpFile" -Value $DumpFile
