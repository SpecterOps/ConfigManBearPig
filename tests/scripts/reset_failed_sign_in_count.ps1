# Signs in once as the account with its correct password. A successful sign-in makes the
# domain controller reset the account's failed sign-in count to 0. Then prints the count.
# Run it before a wrong-password check, so the check starts from 0, and again afterwards.
#
# Example:
#   .\tests\scripts\reset_failed_sign_in_count.ps1 -Account lowpriv -Password password
param(
    [Parameter(Mandatory)] [string] $Account,
    [Parameter(Mandatory)] [string] $Password
)

. "$PSScriptRoot\lab_helpers.ps1"
Assert-LabAddress 'dc.mayyhem.com'

# Reading the domain's top entry with these credentials is the sign-in.
$entry = New-Object System.DirectoryServices.DirectoryEntry('LDAP://dc.mayyhem.com/DC=mayyhem,DC=com', "MAYYHEM\$Account", $Password)
try { $entry.RefreshCache() } finally { $entry.Dispose() }
& "$PSScriptRoot\get_failed_sign_in_count.ps1" -Account $Account
