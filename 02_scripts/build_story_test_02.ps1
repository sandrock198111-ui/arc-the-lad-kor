Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$originalZip = Join-Path $root '00_original\arc.zip'
$glyphZip = Join-Path $root 'ex\1.zip'
$glyphBackup = Join-Path $root '99_backup\ex1_manifest_source.zip'
$workRoot = Join-Path $root '01_work\story_test_02'
$workFont = Join-Path $workRoot 'COMM.IMG'
$workDat = Join-Path $workRoot '1\S1071.DAT'
$outputZip = Join-Path $root '03_output\story_test_02_s1071_charmap_patch_only.zip'

New-Item -ItemType Directory -Force -Path (Split-Path $glyphBackup), (Split-Path $workDat), (Split-Path $outputZip) | Out-Null

if (-not (Test-Path -LiteralPath $glyphBackup)) {
    Copy-Item -LiteralPath $glyphZip -Destination $glyphBackup
} elseif ((Get-FileHash $glyphZip).Hash -ne (Get-FileHash $glyphBackup).Hash) {
    throw "Backup exists but does not match ex\1.zip: $glyphBackup"
}

if ((Test-Path -LiteralPath $workFont) -or (Test-Path -LiteralPath $workDat) -or (Test-Path -LiteralPath $outputZip)) {
    throw 'Story test 02 already exists. Refusing to overwrite it.'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

function Read-ZipEntryBytes {
    param([string]$ZipPath, [string]$EntryName)
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entry = $archive.GetEntry($EntryName)
        if ($null -eq $entry) {
            throw "Archive entry not found: $EntryName"
        }
        $memory = [System.IO.MemoryStream]::new()
        $input = $entry.Open()
        try {
            $input.CopyTo($memory)
            return $memory.ToArray()
        } finally {
            $input.Dispose()
            $memory.Dispose()
        }
    } finally {
        $archive.Dispose()
    }
}

$font = Read-ZipEntryBytes $originalZip 'COMM.IMG'
$glyphSource = Read-ZipEntryBytes $glyphZip 'COMM.IMG'
$dat = Read-ZipEntryBytes $originalZip '1/S1071.DAT'

if ($font.Length -ne 458752 -or $glyphSource.Length -ne 458752) {
    throw 'Unexpected COMM.IMG size.'
}
if ($dat.Length -ne 305152) {
    throw 'Unexpected S1071.DAT size.'
}

# Each 12-pixel-wide 4bpp cell occupies exactly 6 bytes per row.
# code 0x04 points to cell 0 and is used as a blank filler.
for ($y = 0; $y -lt 12; $y++) {
    $rowOffset = $y * 0x380
    for ($byte = 0; $byte -lt 6; $byte++) {
        $font[$rowOffset + $byte] = 0
    }
}

# ex/1.zip contains these 24 one-bit glyphs in this exact order.
# Source atlas: x=104, y=39, 12x12 cells laid out horizontally.
# Use Unicode code points so Windows PowerShell 5 does not depend on file encoding.
$characters = @(
    0xC5EC, 0xAE30, 0xAE4C, 0xC9C0, 0xB2E4, 0xC774,
    0xB4A4, 0xB294, 0xD63C, 0xC790, 0xAC00, 0xB77C,
    0xC544, 0xD06C, 0xC870, 0xC2EC, 0xD558, 0xAC70,
    0xB3CC, 0xC62C, 0xB54C, 0xB9AC, 0xACA0, 0xC608
) | ForEach-Object { [string][char]$_ }
$codes = @{}
for ($index = 0; $index -lt $characters.Count; $index++) {
    $code = 0x08 + $index * 4
    $codes[$characters[$index]] = [byte]$code

    # code 0x04 is cell 0, so code 0x08 begins at cell 1.
    $cell = $index + 1
    $destinationByteX = ($cell % 21) * 6
    $destinationY = [int][Math]::Floor($cell / 21) * 12
    $sourceByteX = 52 + $index * 6
    $sourceY = 39

    for ($y = 0; $y -lt 12; $y++) {
        $sourceOffset = ($sourceY + $y) * 0x380 + $sourceByteX
        $destinationOffset = ($destinationY + $y) * 0x380 + $destinationByteX
        for ($byte = 0; $byte -lt 6; $byte++) {
            $font[$destinationOffset + $byte] = $glyphSource[$sourceOffset + $byte]
        }
    }
}

function Encode-Text {
    param([string[]]$Lines, [hashtable]$CodeMap)
    $encoded = [System.Collections.Generic.List[byte]]::new()
    for ($lineIndex = 0; $lineIndex -lt $Lines.Count; $lineIndex++) {
        if ($lineIndex -gt 0) {
            $encoded.Add(0xE6)
            $encoded.Add(0x01)
        }
        foreach ($character in $Lines[$lineIndex].ToCharArray()) {
            $key = [string]$character
            if (-not $CodeMap.ContainsKey($key)) {
                throw "No code assigned for character: $key"
            }
            $encoded.Add($CodeMap[$key])
        }
    }
    return $encoded.ToArray()
}

function New-Text {
    param([int[]]$CodePoints)
    return -join ($CodePoints | ForEach-Object { [char]$_ })
}

$patches = @(
    @{ Start = 0x478D6; Length = 39; Lines = @(
        (New-Text @(0xC5EC,0xAE30,0xAE4C,0xC9C0,0xB2E4)),
        (New-Text @(0xC774,0xB4A4,0xB294,0xD63C,0xC790,0xAC00,0xB77C))
    ); Terminator = 0x478FD },
    @{ Start = 0x47932; Length = 41; Lines = @(
        (New-Text @(0xC544,0xD06C,0xC5EC)),
        (New-Text @(0xC870,0xC2EC,0xD558,0xAC70,0xB77C))
    ); Terminator = 0x4795B },
    @{ Start = 0x4798E; Length = 55; Lines = @(
        (New-Text @(0xB3CC,0xC544,0xC62C,0xB54C,0xAE4C,0xC9C0)),
        (New-Text @(0xAE30,0xB2E4,0xB9AC,0xACA0,0xB2E4))
    ); Terminator = 0x479C5 },
    @{ Start = 0x479FA; Length = 6; Lines = @(
        (New-Text @(0xC608))
    ); Terminator = 0x47A00 }
)

foreach ($patch in $patches) {
    if ($dat[$patch.Terminator] -ne 0x00) {
        throw ('Expected 0x00 terminator at 0x{0:X}' -f $patch.Terminator)
    }
    [byte[]]$encoded = @(Encode-Text $patch.Lines $codes)
    if ($encoded.Length -gt $patch.Length) {
        throw "Encoded text exceeds block length at 0x$($patch.Start.ToString('X'))"
    }
    for ($i = 0; $i -lt $patch.Length; $i++) {
        $dat[$patch.Start + $i] = 0x04
    }
    [Array]::Copy($encoded, 0, $dat, $patch.Start, $encoded.Length)
}

[System.IO.File]::WriteAllBytes($workFont, $font)
[System.IO.File]::WriteAllBytes($workDat, $dat)

Compress-Archive -LiteralPath $workFont, (Join-Path $workRoot '1'), (Join-Path $workRoot 'TEST_INFO.txt'), (Join-Path $workRoot 'CHARMAP.txt') -DestinationPath $outputZip -CompressionLevel Optimal

Get-FileHash -Algorithm SHA256 -LiteralPath $glyphBackup, $workFont, $workDat, $outputZip |
    Select-Object Path, Hash
