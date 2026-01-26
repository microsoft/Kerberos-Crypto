
$shared = Join-Path $PSScriptRoot "Shared"
$kerberos = Join-Path $PSScriptRoot "Kerberos"
$kdc = Join-Path $PSScriptRoot "KDC"

Get-ChildItem $shared -Filter *.ps1 -File -ErrorAction Ignore | ForEach-Object { . $_.FullName }
Get-ChildItem $kerberos -Filter *.ps1 -File -ErrorAction Ignore | ForEach-Object {
    . $_.FullName
    Export-ModuleMember -Function $_.BaseName
}

$role = (Get-WmiObject Win32_ComputerSystem).DomainRole

Write-Verbose "Machine operating as role $role"

$BACKUP_DOMAIN_CONTROLLER = 4
$PRIMARY_DOMAIN_CONTROLLER = 5

if ($BACKUP_DOMAIN_CONTROLLER -eq $role -or $PRIMARY_DOMAIN_CONTROLLER -eq $role) {
    Write-Verbose "Importing KDC module"
    Get-ChildItem $kdc -Filter *.ps1 -File -ErrorAction Ignore | ForEach-Object {
        . $_.FullName
        Export-ModuleMember -Function $_.BaseName
    }
}
