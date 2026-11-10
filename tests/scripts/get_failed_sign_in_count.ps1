# Prints how many wrong-password sign-ins the domain controller has counted for an account
# since that account last signed in successfully (the account's "badPwdCount"). The lab has
# one domain controller, so its count is the whole story. Reads it as the Windows account
# running this script.
#
# Example:
#   .\tests\scripts\get_failed_sign_in_count.ps1 -Account lowpriv
param([Parameter(Mandatory)] [string] $Account)

. "$PSScriptRoot\lab_helpers.ps1"
Assert-LabAddress 'dc.mayyhem.com'

$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]'LDAP://dc.mayyhem.com/DC=mayyhem,DC=com')
$searcher.Filter = "(sAMAccountName=$Account)"
[void]$searcher.PropertiesToLoad.Add('badpwdcount')
$found = $searcher.FindOne()
if (-not $found) { throw "There is no account named $Account in mayyhem.com." }
"Failed sign-ins counted for ${Account}: $([int]$found.Properties['badpwdcount'][0])"
