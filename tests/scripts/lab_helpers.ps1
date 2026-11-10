# Shared helper for the lab check scripts in this folder. Each script loads this file first.
#
# These scripts are only for the mayyhem.com research lab. Testing is allowed only against
# 10.10.10.0/24 and 10.10.11.0/24, so every script refuses to contact a computer whose name
# points anywhere else.

function Assert-LabAddress {
    # Stops the script if the name does not resolve, or points outside the two lab ranges.
    param([Parameter(Mandatory)] [string] $Name)
    $addresses = @((Resolve-DnsName $Name -Type A -ErrorAction Stop | Where-Object Type -eq 'A').IPAddress)
    if ($addresses.Count -eq 0) { throw "$Name did not resolve to an address." }
    foreach ($address in $addresses) {
        if ($address -notmatch '^10\.10\.1[01]\.\d{1,3}$') {
            throw "$Name points to $address, which is outside the lab ranges 10.10.10.0/24 and 10.10.11.0/24."
        }
    }
}
