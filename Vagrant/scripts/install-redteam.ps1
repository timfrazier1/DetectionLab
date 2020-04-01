# Purpose: Installs Mimikatz and Powersploit into c:\Tools\Mimikatz. Used to install redteam related tooling.

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Red Team Tooling..."

# Windows Defender should be disabled already by O&O ShutUp10
If ($hostname -eq "win10") {
  # Adding Defender exclusions just in case
  Set-MpPreference -ExclusionPath "C:\Tools"
  Add-MpPreference -ExclusionPath "C:\Users\vagrant\AppData\Local\Temp"
  Add-MpPreference -DisableRealtimeMonitoring $true
}

# Purpose: Downloads and unzips a copy of the latest Mimikatz trunk
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Determining latest release of Mimikatz..."
# GitHub requires TLS 1.2 as of 2/27
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tag = (Invoke-WebRequest "https://api.github.com/repos/gentilkiwi/mimikatz/releases" -UseBasicParsing | ConvertFrom-Json)[0].tag_name
$mimikatzDownloadUrl = "https://github.com/gentilkiwi/mimikatz/releases/download/$tag/mimikatz_trunk.zip"
$mimikatzRepoPath = 'C:\Users\vagrant\AppData\Local\Temp\mimikatz_trunk.zip'
if (-not (Test-Path $mimikatzRepoPath)) {
  Invoke-WebRequest -Uri "$mimikatzDownloadUrl" -OutFile $mimikatzRepoPath
  Expand-Archive -path "$mimikatzRepoPath" -destinationpath 'c:\Tools\Mimikatz' -Force
}
else {
  Write-Host "Mimikatz was already installed. Moving On."
}

# Download and unzip a copy of PowerSploit
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Powersploit..."
# GitHub requires TLS 1.2 as of 2/27
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$powersploitDownloadUrl = "https://github.com/PowerShellMafia/PowerSploit/archive/dev.zip"
$powersploitRepoPath = "C:\Users\vagrant\AppData\Local\Temp\powersploit.zip"
if (-not (Test-Path $powersploitRepoPath)) {
  Invoke-WebRequest -Uri "$powersploitDownloadUrl" -OutFile $powersploitRepoPath
  Expand-Archive -path "$powersploitRepoPath" -destinationpath 'c:\Tools\PowerSploit' -Force
  Copy-Item "c:\Tools\PowerSploit\PowerSploit-dev\*" "$Env:windir\System32\WindowsPowerShell\v1.0\Modules" -Recurse -Force
}
else {
  Write-Host "PowerSploit was already installed. Moving On."
}

# Download and unzip a copy of Atomic Red Team
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Atomic Red Team..."
# GitHub requires TLS 1.2 as of 2/27
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$atomicRedTeamDownloadUrl = "https://github.com/redcanaryco/atomic-red-team/archive/master.zip"
$atomicRedTeamRepoPath = "C:\Users\vagrant\AppData\Local\Temp\atomic_red_team.zip"
if (-not (Test-Path $atomicRedTeamRepoPath)) {
  Invoke-WebRequest -Uri "$atomicRedTeamDownloadUrl" -OutFile "$atomicRedTeamRepoPath"
  Expand-Archive -path "$atomicRedTeamRepoPath" -destinationpath 'c:\Tools\Atomic Red Team' -Force
}
else {
  Write-Host "Atomic Red Team was already installed. Moving On."
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Red Team tooling installation complete!"

