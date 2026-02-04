# ============================================================
# Chrysalis Detection Script with Self-Elevation + Persistent Admin Window
# ============================================================

param (
    [switch]$Elevated
)

# ============================================================
# Elevation logic
# ============================================================

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    if (-not $Elevated) {
        Write-Host "[*] Administrator privileges required." -ForegroundColor Yellow
        Write-Host "[*] Requesting elevation..." -ForegroundColor Cyan

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Elevated"
        $psi.Verb = "runas"
        $psi.UseShellExecute = $true

        try {
            [System.Diagnostics.Process]::Start($psi) | Out-Null
            Write-Host "[+] Elevated PowerShell launched." -ForegroundColor Green
        } catch {
            Write-Host "[!] Elevation cancelled." -ForegroundColor Red
        }

        Read-Host "Press ENTER to close this window"
        exit
    }
}

# ============================================================
# ADMIN CONTEXT STARTS HERE
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# Logging setup — FORCE script directory
# ============================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$hostname  = $env:COMPUTERNAME
$timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
$logFile   = Join-Path $scriptDir "$hostname`_$timestamp.txt"

function Log {
    param(
        [string]$msg,
        [string]$color = "White"
    )
    Write-Host $msg -ForegroundColor $color
    Add-Content -Path $logFile -Value $msg
}

Log "--- Starting system scan for Notepad++ Hijack / Chrysalis IoCs ---" "Cyan"
Log "Log file: $logFile" "Cyan"

# ============================================================
# 1. Suspicious directories & files
# ============================================================

$dirsToCheck = @(
    "$env:APPDATA\Bluetooth",
    "$env:APPDATA\ProShow",
    "$env:APPDATA\Adobe\Scripts",
    "$env:APPDATA\Microsoft\Windows\Themes",
    "$env:ProgramData\Windows\Themes",
    "$env:ProgramData\Microsoft\Bluetooth",
    "$env:ProgramData\Microsoft\Windows"
)

$suspiciousNames = @(
    "BluetoothService.exe",
    "log.dll",
    "alien.ini",
    "load",
    "theme.exe",
    "themesvc.exe",
    "btservice.exe",
    "svhost.exe"
)

foreach ($dir in $dirsToCheck) {
    if (Test-Path $dir) {
        Log "[!] ALERT: Suspicious directory present: $dir" "Red"
        Get-ChildItem -Path $dir -File | ForEach-Object {
            if ($suspiciousNames -contains $_.Name) {
                Log "    [!!!] MALWARE COMPONENT DETECTED: $($_.FullName)" "Red"
            } else {
                Log "    [?] File found: $($_.FullName)" "Yellow"
            }
        }
    } else {
        Log "[+] Directory not found: $dir" "Green"
    }
}

# ============================================================
# 2. Process analysis
# ============================================================

$procNames = "BluetoothService","ProShow","theme","themesvc","btservice","svhost","nsis","update"

foreach ($name in $procNames) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
        Log "[!] Suspicious process detected: $name" "Red"
        if ($_.Path -and $_.Path -match "AppData|ProgramData") {
            Log "    [!!!] Running from data directory: $($_.Path) (PID $($_.Id))" "Red"
        } elseif ($_.Path) {
            Log "    [!] Process path: $($_.Path) (PID $($_.Id))" "Yellow"
        } else {
            Log "    [?] Process path unavailable (PID $($_.Id))" "Yellow"
        }
    }
}

# ============================================================
# 3. Mutex detection
# ============================================================

$mutexName = "Global\Jdhfv_1.0.1"
try {
    $m = [System.Threading.Mutex]::OpenExisting($mutexName)
    Log "[!!!] ALERT: Active Chrysalis mutex detected: $mutexName" "Red"
    $m.Close()
} catch {
    Log "[+] Chrysalis mutex not found: $mutexName" "Green"
}

# ============================================================
# 4. TEMP directory check
# ============================================================

$tempPath = $env:TEMP
$badFiles = "update.exe","AutoUpdater.exe","npp_update.exe"

foreach ($bf in $badFiles) {
    $fp = Join-Path $tempPath $bf
    if (Test-Path $fp) {
        Log "[!] Suspicious TEMP file: $fp" "Yellow"
    }
}

Get-ChildItem $tempPath -Filter "ns*.tmp" | ForEach-Object {
    Log "[?] NSIS-related temp file: $($_.FullName)" "Yellow"
}

# ============================================================
# 5. Hash IoCs
# ============================================================

$knownHashes = @(
    "8e6e505438c21f3d281e1cc257abdbf7223b7f5a",
    "573549869e84544e3ef253bdba79851dcde4963a",
    "4c9aac447bf732acc97992290aa7a187b967ee2c"
)

foreach ($bf in $badFiles) {
    $fp = Join-Path $tempPath $bf
    if (Test-Path $fp) {
        $hash = (Get-FileHash $fp -Algorithm SHA1).Hash.ToLower()
        if ($knownHashes -contains $hash) {
            Log "[!!!] CRITICAL: Known malicious hash match: $fp" "Red"
        } else {
            Log "[+] Hash OK: $fp" "Green"
        }
    }
}

# ============================================================
# 6. Network IoCs
# ============================================================

$badDomains = "cdncheck.it.com","safe-dns.it.com","self-dns.it.com","update-checker.online","winupdate-service.com"
$badIPs     = "45.77.31.210","45.76.155.202","95.179.213.0","104.168.214.52","149.28.44.125"

$dnsCache = ipconfig /displaydns
foreach ($d in $badDomains) {
    if ($dnsCache -match [regex]::Escape($d)) {
        Log "[!!!] ALERT: DNS cache hit: $d" "Red"
    }
}

$netstat = netstat -ano
foreach ($ip in $badIPs) {
    if ($netstat -match [regex]::Escape($ip)) {
        Log "[!!!] ALERT: Network connection to malicious IP: $ip" "Red"
    }
}

# ============================================================
# 7. Summary
# ============================================================

Log "--- Scan complete ---" "Cyan"
Log "Results saved to: $logFile" "Cyan"

Write-Host ""
Write-Host "========== SUMMARY ==========" -ForegroundColor Cyan
Write-Host "Scan completed successfully."
Write-Host "Log file saved at:"
Write-Host "  $logFile" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Cyan

Read-Host "Press ENTER to close this window"
