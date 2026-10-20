# windows-prep.ps1 - stage offensive tooling on a Windows attacker box.
# Supported: Windows 10/11 and Windows Server 2016/2019/2022/2025 (PowerShell 5.1+).
# Software is always pulled at its latest version; nothing is version-pinned.

# Continue past non-terminating errors; each step below catches its own terminating errors.
$ErrorActionPreference = "Continue"

# Use TLS 1.2+ so downloads from GitHub and python.org succeed on default Windows configs
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$WebClient = New-Object Net.WebClient

# ---- Output helpers (clear, color-coded, per-step status) -------------------
function Write-Step([string]$m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Note([string]$m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Fail([string]$m) { Write-Host "[-] $m" -ForegroundColor Red }

$script:Failures = @()
function Invoke-Step([string]$Name, [scriptblock]$Action) {
    Write-Step "$Name ..."
    try {
        & $Action
        Write-Ok "$Name succeeded"
    } catch {
        Write-Fail "$Name FAILED: $($_.Exception.Message)"
        $script:Failures += $Name
    }
}

# Run an installer and treat a non-zero/non-reboot exit code as a clear failure
function Invoke-Installer([string]$FilePath, [string[]]$Arguments) {
    $p = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru
    if ($p.ExitCode -notin 0, 3010) { throw "$FilePath exited with code $($p.ExitCode)" }
}

# Resolve the download URL of the latest GitHub release asset matching a name pattern
function Get-LatestReleaseAsset([string]$Repo, [string]$Pattern) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
    $asset = $release.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
    if (-not $asset) { throw "no asset matching '$Pattern' in latest release of $Repo (tag $($release.tag_name))" }
    $asset.browser_download_url
}

# ---- Environment detection --------------------------------------------------
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {
    $os = Get-WmiObject Win32_OperatingSystem
}
# ProductType: 1 = workstation (Win10/11), 2 = domain controller, 3 = server
$isServer = $os.ProductType -ne 1
$build    = [int]$os.BuildNumber
$isAdmin  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "==== Windows prep ====" -ForegroundColor White
Write-Host "OS:          $($os.Caption)"
Write-Host "Version:     $($os.Version) (build $build)"
Write-Host "Type:        $(if ($isServer) { 'Server' } else { 'Client' })"
Write-Host "PowerShell:  $($PSVersionTable.PSVersion)"
Write-Host "Elevated:    $isAdmin"
Write-Host ""

if ($build -lt 10240) {
    Write-Note "Build $build looks older than Windows 10 / Server 2016. This script targets Windows 10/11 and Server 2016/2019/2022/2025; some steps may not work."
}
if (-not $isAdmin) {
    Write-Note "Not running as Administrator. RSAT, DSInternals, and the MSI/installer steps will likely fail - re-run this script in an elevated PowerShell for full results."
}

# ---- Tools directory --------------------------------------------------------
$Tools = "$env:SystemDrive\Tools"
Invoke-Step "Create tools directory ($Tools)" { New-Item -ItemType Directory -Path $Tools -Force -ErrorAction Stop | Out-Null }

# ---- Direct file downloads (always-latest sources) --------------------------
# jakobfriedl/precompiled-binaries, the mimikatz mirror, and the raw scripts all
# track their default branch, so they are already always-latest. SigmaPotato and
# Snaffler use version-less asset names, so /releases/latest/download resolves the
# newest build without pinning a version.
$Downloads = [ordered]@{
    "Rubeus.exe"          = "https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/Rubeus.exe"
    "Certify.exe"         = "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/CertificateAbuse/Certify.exe"
    "Seatbelt.exe"        = "https://github.com/jakobfriedl/precompiled-binaries/raw/main/Enumeration/Seatbelt.exe"
    "SharpGPOAbuse.exe"   = "https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/GPOAbuse/SharpGPOAbuse.exe"
    "SharpSCCM.exe"       = "https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/SharpSCCM.exe"
    "Whisker.exe"         = "https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/Whisker.exe"
    "SharpDPAPI.exe"      = "https://github.com/jakobfriedl/precompiled-binaries/raw/main/Credentials/SharpDPAPI.exe"
    "SigmaPotato.exe"     = "https://github.com/tylerdotrar/SigmaPotato/releases/latest/download/SigmaPotato.exe"
    "Snaffler.exe"        = "https://github.com/SnaffCon/Snaffler/releases/latest/download/Snaffler.exe"
    "mimikatz.exe"        = "https://github.com/parrotsec/mimikatz/raw/master/x64/mimikatz.exe"
    "dsinternalparser.py" = "https://raw.githubusercontent.com/Commotio/DSInternalsParser/refs/heads/main/dsinternalparser.py"
    "PowerUpSQL.ps1"      = "https://github.com/NetSPI/PowerUpSQL/raw/master/PowerUpSQL.ps1"
    "PowerView.ps1"       = "https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1"
    "SharpHound.ps1"      = "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1"
}
foreach ($name in $Downloads.Keys) {
    $url = $Downloads[$name]
    Invoke-Step "Download $name" { $WebClient.DownloadFile($url, "$Tools\$name") }.GetNewClosure()
}

# ---- PingCastle (latest release; asset name carries the version) ------------
Invoke-Step "Install PingCastle (latest)" {
    $url = Get-LatestReleaseAsset "netwrix/pingcastle" '^PingCastle_.*\.zip$'
    $WebClient.DownloadFile($url, "$Tools\PingCastle.zip")
    Expand-Archive -Path "$Tools\PingCastle.zip" -DestinationPath "$Tools\PingCastle" -Force -ErrorAction Stop
    Remove-Item -Path "$Tools\PingCastle.zip" -Force -ErrorAction SilentlyContinue
}

# ---- RSAT (AD + GroupPolicy PowerShell) - path depends on client vs server --
if ($isServer) {
    Invoke-Step "Install RSAT AD + GPMC features (Windows Server)" {
        $feat = Get-WindowsFeature -Name RSAT-AD-PowerShell, RSAT-ADDS, GPMC -ErrorAction Stop | Where-Object InstallState -eq 'Available'
        if ($feat) { $feat | Install-WindowsFeature -ErrorAction Stop | Out-Null }
    }
} else {
    Invoke-Step "Install RSAT AD + Group Policy capabilities (Windows client)" {
        # -Name takes a single wildcard, so query each capability family separately
        $caps = @('Rsat.ActiveDirectory*', 'Rsat.GroupPolicy.Management.Tools*') |
            ForEach-Object { Get-WindowsCapability -Name $_ -Online -ErrorAction Stop } |
            Where-Object State -ne 'Installed'
        if ($caps) { $caps | Add-WindowsCapability -Online -ErrorAction Stop | Out-Null }
    }
}

# ---- DSInternals module (needs NuGet provider + PSGallery) ------------------
Invoke-Step "Install DSInternals PowerShell module" {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    Install-Module DSInternals -Force -Scope AllUsers -ErrorAction Stop
}

# ---- Notepad++ (latest release) --------------------------------------------
Invoke-Step "Install Notepad++ (latest)" {
    if (Test-Path "$env:ProgramFiles\Notepad++\notepad++.exe") {
        Write-Note "Notepad++ already installed - skipping"
        return
    }
    $url = Get-LatestReleaseAsset "notepad-plus-plus/notepad-plus-plus" 'Installer\.x64\.exe$'
    $exe = "$env:USERPROFILE\Downloads\npp.exe"
    $WebClient.DownloadFile($url, $exe)
    Invoke-Installer $exe @("/S")
    Remove-Item -Path $exe -Force -ErrorAction SilentlyContinue
}

# ---- Python (latest stable 3.x, resolved from python.org) -------------------
Invoke-Step "Install Python 3 (latest)" {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        Write-Note "python already on PATH - skipping"
        return
    }
    $pyVer = (Invoke-WebRequest "https://www.python.org/ftp/python/" -UseBasicParsing).Links.href |
        Where-Object { $_ -match '^3(\.\d+){2}/$' } |
        ForEach-Object { $_.TrimEnd('/') } |
        Sort-Object { [version]$_ } |
        Select-Object -Last 1
    if (-not $pyVer) { throw "could not determine latest Python version from python.org" }
    $exe = "$env:USERPROFILE\Downloads\python.exe"
    $WebClient.DownloadFile("https://www.python.org/ftp/python/$pyVer/python-$pyVer-amd64.exe", $exe)
    Invoke-Installer $exe @("/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0")
    Remove-Item -Path $exe -Force -ErrorAction SilentlyContinue
}

# ---- MobaXterm (latest Home Edition; MSI name discovered, not hardcoded) ----
Invoke-Step "Install MobaXterm (latest)" {
    $page = Invoke-WebRequest "https://mobaxterm.mobatek.net/download-home-edition.html" -UseBasicParsing
    $zipUrl = $page.Links.href | Where-Object { $_ -match 'MobaXterm_Installer_v[\d.]+\.zip$' } | Select-Object -First 1
    if (-not $zipUrl) { throw "could not find the installer link on the MobaXterm download page" }
    if ($zipUrl -notmatch '^https?://') { $zipUrl = "https://mobaxterm.mobatek.net/$($zipUrl.TrimStart('/'))" }
    $zip = "$env:USERPROFILE\Downloads\MobaXterm.zip"
    $dir = "$env:USERPROFILE\Downloads\MobaXterm"
    $WebClient.DownloadFile($zipUrl, $zip)
    Expand-Archive -Path $zip -DestinationPath $dir -Force -ErrorAction Stop
    # Discover the MSI rather than hardcoding its name (the zip and MSI version strings differ)
    $msi = (Get-ChildItem -Path $dir -Filter "*.msi" -Recurse | Select-Object -First 1).FullName
    if (-not $msi) { throw "no MSI found inside the downloaded MobaXterm archive" }
    Invoke-Installer "msiexec.exe" @("/i", "`"$msi`"", "/quiet", "/qn", "/norestart")
    Remove-Item -Path $zip -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- Summary ----------------------------------------------------------------
Write-Host ""
if ($script:Failures.Count -eq 0) {
    Write-Ok "Installation complete - all steps succeeded. Tools are in $Tools."
} else {
    Write-Note "Installation finished with $($script:Failures.Count) failed step(s):"
    $script:Failures | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
    Write-Note "Re-run elevated and with internet access to retry the failed steps. Tools that did download are in $Tools."
}
