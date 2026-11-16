<#
Preview by default. -Apply compacts only Docker Desktop's existing data VHDX.
Stop Docker Desktop and all WSL workloads yourself before applying. This script
does not stop services, delete files, move disks or change their virtual capacity.
#>
[CmdletBinding()]
param([switch]$Apply)

$ErrorActionPreference = 'Stop'
$dockerRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Docker\wsl'))
$diskPath = Join-Path $dockerRoot 'disk\docker_data.vhdx'
$diskItem = Get-Item -LiteralPath $diskPath
$resolvedDisk = $diskItem.FullName
if (-not $resolvedDisk.StartsWith($dockerRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Resolved disk is outside Docker Desktop storage.'
}
if ($diskItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw 'Refusing a reparse point for the Docker data disk.'
}
$beforeBytes = $diskItem.Length
Write-Output ('Docker data disk: ' + $resolvedDisk)
Write-Output ('Current file size: {0:N2} GiB' -f ($beforeBytes / 1GB))
if (-not $Apply) {
    Write-Output 'Preview only. After stopping Docker Desktop and WSL, rerun from an elevated PowerShell with -Apply.'
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Compaction requires an elevated PowerShell.'
}
if (Get-Process -Name 'com.docker.backend','Docker Desktop','vmmemWSL' -ErrorAction SilentlyContinue) {
    throw 'Docker Desktop or WSL is still running. Stop workloads and run wsl --shutdown first.'
}
# A final exclusive-open check rejects any attached or otherwise locked disk.
$probe = [System.IO.File]::Open($resolvedDisk, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
$probe.Dispose()
if (Get-Command Optimize-VHD -ErrorAction SilentlyContinue) {
    Optimize-VHD -Path $resolvedDisk -Mode Full
} else {
    # DiskPart ships with Windows even without the Hyper-V PowerShell module.
    # Only select/compact a detached, fixed-path disk; never attach writable,
    # resize, format, delete, or operate on a physical disk.
    if ($resolvedDisk.Contains('"') -or $resolvedDisk.Contains("`n") -or $resolvedDisk.Contains("`r")) {
        throw 'Unsafe disk path for DiskPart.'
    }
    $diskpartInput = [System.IO.Path]::GetTempFileName()
    try {
        $commands = 'select vdisk file="' + $resolvedDisk + '"' + "`r`ncompact vdisk`r`nexit`r`n"
        [System.IO.File]::WriteAllText($diskpartInput, $commands, [System.Text.Encoding]::Default)
        & "$env:SystemRoot\System32\diskpart.exe" /s $diskpartInput
        if ($LASTEXITCODE -ne 0) { throw ('DiskPart failed with exit code ' + $LASTEXITCODE) }
    } finally {
        Remove-Item -LiteralPath $diskpartInput -Force -ErrorAction SilentlyContinue
    }
}
$afterBytes = (Get-Item -LiteralPath $resolvedDisk).Length
Write-Output ('After compaction: {0:N2} GiB; file reduction: {1:N2} GiB' -f ($afterBytes / 1GB), (($beforeBytes - $afterBytes) / 1GB))
Write-Output 'Start Docker Desktop, then restore the containers that were running before maintenance.'
