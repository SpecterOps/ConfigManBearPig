# Reads a collection run's full log and shows:
#   1. each short computer name the collector decided to treat as a full name, and
#   2. every computer the collector visited, as the per-computer log lines name it.
# Each computer should be listed once, by its full name.
#
# Example:
#   .\tests\scripts\show_computers_visited.ps1 -OutputFolder $out
param([Parameter(Mandatory)] [string] $OutputFolder)

$log = Get-ChildItem $OutputFolder -Filter 'collect_full_*.log' | Select-Object -First 1
if (-not $log) { throw "There is no collect_full_*.log file in $OutputFolder." }

'Short names treated as full names:'
$merged = @(Select-String -Path $log.FullName -Pattern "Treating '[^']+' as '[^']+'" | ForEach-Object { $_.Matches[0].Value } | Sort-Object -Unique)
if ($merged.Count -eq 0) { '  (none)' } else { $merged | ForEach-Object { "  $_" } }

# Per-computer log lines start with the computer and the collection method, for example
# "[ps1-mp.mayyhem.com][SMB]".
'Computers visited:'
Select-String -Path $log.FullName -Pattern '\[([A-Za-z0-9_.-]+)\]\[(SMB|WMI|AdminService|HTTP|RemoteRegistry|MSSQL)\]' -AllMatches |
    ForEach-Object { $_.Matches | ForEach-Object { $_.Groups[1].Value } } |
    Sort-Object -Unique |
    ForEach-Object { "  $_" }
