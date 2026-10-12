#Requires -RunAsAdministrator
# Give a Hyper-V Linux guest a GPU-PV partition of the host GPU, and
# optionally a data disk for the builds. See README.md ("Inside a Hyper-V
# VM"). The VM is shut down if it runs and started again at the end.
#
# Usage: hyperv-gpupv.ps1 -VMName NAME [-DataDisk PATH.vhdx] [-DataDiskSize 40GB]
param(
    [Parameter(Mandatory = $true)][string]$VMName,
    [string]$DataDisk,
    [uint64]$DataDiskSize = 40GB
)
$ErrorActionPreference = 'Stop'

$gpus = if (Get-Command Get-VMHostPartitionableGpu -ErrorAction SilentlyContinue) { Get-VMHostPartitionableGpu } else { Get-VMPartitionableGpu }
if (-not $gpus) { throw 'No partitionable GPU on this host' }
$gpus | Format-List Name, PartitionCount

$v = Get-VM $VMName
$v | Format-List Name, State, Generation, DynamicMemoryEnabled, MemoryStartup, AutomaticStopAction, AutomaticCheckpointsEnabled
if ($v.State -ne 'Off') {
    Write-Host "Shutting $VMName down..."
    Stop-VM $VMName
}

# A VM with a GPU partition can be neither saved nor checkpointed.
Set-VM $VMName -AutomaticCheckpointsEnabled $false -AutomaticStopAction ShutDown `
    -GuestControlledCacheTypes $true -LowMemoryMappedIoSpace 1GB -HighMemoryMappedIoSpace 32GB

if (-not (Get-VMGpuPartitionAdapter $VMName -ErrorAction SilentlyContinue)) { Add-VMGpuPartitionAdapter $VMName }
Set-VMGpuPartitionAdapter $VMName `
    -MinPartitionVRAM 80000000 -MaxPartitionVRAM 100000000 -OptimalPartitionVRAM 100000000 `
    -MinPartitionEncode 80000000 -MaxPartitionEncode 100000000 -OptimalPartitionEncode 100000000 `
    -MinPartitionDecode 80000000 -MaxPartitionDecode 100000000 -OptimalPartitionDecode 100000000 `
    -MinPartitionCompute 80000000 -MaxPartitionCompute 100000000 -OptimalPartitionCompute 100000000

if ($DataDisk) {
    if (-not (Test-Path $DataDisk)) { New-VHD -Path $DataDisk -SizeBytes $DataDiskSize -Dynamic | Out-Null }
    if (-not (Get-VMHardDiskDrive $VMName | Where-Object Path -eq $DataDisk)) { Add-VMHardDiskDrive $VMName -Path $DataDisk }
}

Start-VM $VMName
Get-VMGpuPartitionAdapter $VMName | Format-List
Get-VMHardDiskDrive $VMName | Format-Table ControllerType, ControllerNumber, ControllerLocation, Path
