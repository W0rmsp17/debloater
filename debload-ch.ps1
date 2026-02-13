<#
Usage:
iwr https://yoururl/optimise.ps1 | iex
Optional:
-LogPath "C:\Temp\optimise.log"
-AggressiveVisuals   (only UI/UX perf tweaks, still enterprise-safe)
#>

param(
    [switch]$AggressiveVisuals,
    [string]$LogPath
)
$Script:Messages = @()
function Log { param([string]$m) $Script:Messages += $m }
function Flush-Log {
    if ($LogPath) {
        $dir = Split-Path -Parent $LogPath
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $Script:Messages | Out-File -FilePath $LogPath -Encoding UTF8 -Force
    }
}
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { return }

    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($os -notmatch "Windows 10|Windows 11") { return }
} catch { return }

Log "Start enterprise optimisation"

function Set-RegDword { param($Path,$Name,$Value)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}
function Set-RegString { param($Path,$Name,$Value)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
}
function Set-ServiceManual { param($Name)
    try { Set-Service -Name $Name -StartupType Manual -ErrorAction SilentlyContinue } catch {}
}
function Stop-DisableService { param($Name)
    try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch {}
    try { Set-Service  -Name $Name -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
}
function Disable-TaskExact { param($TaskFullPath)
    try {
        $tp = Split-Path $TaskFullPath
        $tn = Split-Path $TaskFullPath -Leaf
        Disable-ScheduledTask -TaskPath "$tp\" -TaskName $tn -ErrorAction SilentlyContinue | Out-Null
    } catch {}
}
function Remove-AppxSafe { param([string[]]$Patterns)
    foreach ($p in $Patterns) {
        try {
            Get-AppxPackage -AllUsers $p -ErrorAction SilentlyContinue | ForEach-Object {
                try { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue } catch {}
            }
        } catch {}
    }
}
function Has-SSD {
    try { return [bool](Get-PhysicalDisk | Where-Object {$_.MediaType -eq "SSD"}) } catch { return $false }
}


Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerFeatures" 1
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" "AllowNewsAndInterests" 0
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" "ChatIcon" 3
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" 1
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" "EnableAutomaticUploadBandwidthManagement" 1

if ($AggressiveVisuals) {
    Set-RegDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2
}

try {
    $cr = "HKLM:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $cr)) { New-Item -Path $cr -Force | Out-Null }
    Set-ItemProperty -Path $cr -Name "(default)" -Value "" -ErrorAction SilentlyContinue
} catch {}

Set-ServiceManual "WSearch"


if (Has-SSD) { Stop-DisableService "SysMain" }


try { powercfg -h off | Out-Null } catch {}


try {
    Set-MpPreference -ScanAvgCPULoadFactor 20 -ErrorAction SilentlyContinue
} catch {}


$apps = @(
    "Microsoft.Xbox*",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.BingSports",
    "Microsoft.BingFinance",
    "Microsoft.Todos",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People",
    "Microsoft.PowerAutomateDesktop",
    "Microsoft.3DBuilder",
    "Microsoft.MixedReality.Portal",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.SkypeApp",
    "Microsoft.MicrosoftStickyNotes"
)
Remove-AppxSafe $apps


$taskList = @(
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
)
foreach ($t in $taskList) { Disable-TaskExact $t }

# =========================
# Explicitly NOT doing (enterprise safety):
# - AllowTelemetry=0
# - Disabling DiagTrack/dmwappushservice
# - Disabling WSearch
# - Defender exclusions
# - Disabling Windows Update / Delivery Optimisation services
# =========================

Log "Done"
Flush-Log
