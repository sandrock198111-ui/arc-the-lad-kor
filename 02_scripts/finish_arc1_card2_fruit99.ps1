param([int]$DuckProcessId = 11268)
$ErrorActionPreference = 'Stop'
Wait-Process -Id $DuckProcessId -ErrorAction SilentlyContinue
$cardPath = 'C:\Users\Administrator\AppData\Local\DuckStation\memcards\shared_card_2.mcd'
$cardBytes = [IO.File]::ReadAllBytes($cardPath)
if ($cardBytes.Length -ne 131072) { throw 'Unexpected card size' }
$entry = [Text.Encoding]::ASCII.GetString($cardBytes, 394, 20)
if ($entry -ne 'BISCPS-10008ARC1-003') { throw 'File3 identity changed' }
$sum = 0
for ($i = 0x6100; $i -lt 0x6A79; $i++) { $sum += $cardBytes[$i] }
if (($sum -band 255) -ne $cardBytes[0x6A79]) { throw 'Checksum mismatch' }
if ($cardBytes[0x6112] -ne 99) {
    $backupPath = 'E:\korean\99_backup\card2_before_exit_fruit99_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.mcd'
    [IO.File]::WriteAllBytes($backupPath, $cardBytes)
    $sum += 99 - $cardBytes[0x6112]
    $cardBytes[0x6112] = 99
    $cardBytes[0x6A79] = $sum -band 255
    [IO.File]::WriteAllBytes($cardPath, $cardBytes)
}
[IO.File]::WriteAllText('E:\korean\01_work\analysis\v379_card2_fruit99\installed_after_exit.txt', ('Verified quantity99 after DuckStation exit: ' + (Get-Date).ToString('o')))
