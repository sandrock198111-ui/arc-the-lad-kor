Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$sourceZip = Join-Path $root 'ex\2.zip'
$backupZip = Join-Path $root '99_backup\story_v2_original.zip'
$workRoot = Join-Path $root '01_work\story_test_01'
$workDat = Join-Path $workRoot '1\S1071.DAT'
$workFont = Join-Path $workRoot 'COMM.IMG'
$outputZip = Join-Path $root '03_output\story_test_01_patch_only.zip'

if (-not (Test-Path -LiteralPath $sourceZip)) {
    throw "Source archive not found: $sourceZip"
}

New-Item -ItemType Directory -Force -Path (Split-Path $backupZip), (Split-Path $workDat), (Split-Path $outputZip) | Out-Null

if (-not (Test-Path -LiteralPath $backupZip)) {
    Copy-Item -LiteralPath $sourceZip -Destination $backupZip
} elseif ((Get-FileHash $sourceZip).Hash -ne (Get-FileHash $backupZip).Hash) {
    throw "Backup exists but does not match ex\2.zip: $backupZip"
}

if ((Test-Path -LiteralPath $workDat) -or (Test-Path -LiteralPath $workFont) -or (Test-Path -LiteralPath $outputZip)) {
    throw 'Test 01 output already exists. Refusing to overwrite it.'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($sourceZip)
try {
    foreach ($item in @(
        @{ Name = 'COMM.IMG'; Destination = $workFont },
        @{ Name = '1/S1071.DAT'; Destination = $workDat }
    )) {
        $entry = $archive.GetEntry($item.Name)
        if ($null -eq $entry) {
            throw "Archive entry not found: $($item.Name)"
        }
        $input = $entry.Open()
        $output = [System.IO.File]::Create($item.Destination)
        try {
            $input.CopyTo($output)
        } finally {
            $output.Dispose()
            $input.Dispose()
        }
    }
} finally {
    $archive.Dispose()
}

$dat = [System.IO.File]::ReadAllBytes($workDat)
if ($dat.Length -ne 305152) {
    throw "Unexpected S1071.DAT size: $($dat.Length)"
}

$offset = 0x4795B
if ($dat[$offset] -ne 0x04) {
    throw ('Unexpected byte at 0x4795B: 0x{0:X2}' -f $dat[$offset])
}
$dat[$offset] = 0x00
[System.IO.File]::WriteAllBytes($workDat, $dat)

Compress-Archive -LiteralPath $workFont, (Join-Path $workRoot '1'), (Join-Path $workRoot 'TEST_INFO.txt') -DestinationPath $outputZip -CompressionLevel Optimal

Get-FileHash -Algorithm SHA256 -LiteralPath $backupZip, $workFont, $workDat, $outputZip |
    Select-Object Path, Hash
