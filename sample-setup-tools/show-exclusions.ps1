# show-exclusions.ps1 - display WHEA exclusion records

# Check for admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator. Please re-run in an elevated PowerShell session." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Define the registry key path
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WHEA"

# Check if the registry key exists
if (-not (Test-Path $regPath)) {
    Write-Host "Registry key '$regPath' does not exist. Exiting gracefully." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 0
}

# Get the property; if BadPages doesn't exist, it will be $null
$whea = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
$pages = $whea.BadPages

# If BadPages is null or not an array, exit gracefully
if ($null -eq $pages -or $pages -isnot [array]) {
    Write-Host "`nHKLM:\SYSTEM\CurrentControlSet\Control\WHEA\" -ForegroundColor Yellow
    Write-Host "'BadPages' key not present or is empty.`n" -ForegroundColor Yellow
    exit 0
}

# Process the pages
$idx = 0
while ($idx -le $pages.Count) {
    $slice = $pages[$idx..($idx + 7)]
    [array]::Reverse($slice)
    $page = (($slice | ForEach-Object { $_.ToString("X2") }) -join "")
    Write-Output $page
    $idx = $idx + 8
}
