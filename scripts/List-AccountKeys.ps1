<#
.SYNOPSIS
Retrieves the observed Account Key types
.DESCRIPTION
Searches the Security Event Logs for intstances of Event Id 4769 and Event Id 4768 to determine which account keys are used.

.EXAMPLE
List-AccountKeys # This will list all accounts and their key types found in the past 90 days

.PARAMETER Since
Specifies the earliest time to be searched since
.PARAMETER SearchScope
Specifies whether we should search all KDCs in the domain or just the local machine

.NOTES
Author: Will Aftring (wiaftrin)

When specifying AllKdcs, to pull the event log results remote Event Log reading must be enabled.

Copyright (c) Microsoft Corporation. All rights reserved.

#>


[CmdletBinding()]
param(
    [DateTime]$Since = $(Get-Date).AddDays(-30),
    [ValidateSet("DES", "RC4", "AES-SHA1", "All")]
    [string]$ContainsKeyType = "All",
    [ValidateSet("DES", "RC4", "AES-SHA1", "None")]
    [string]$NotContainsKeyType = "None",
    [ValidateSet("This", "AllKdcs")]
    [string]$SearchScope = "This"
)

<#
    N.B(wiaftrin): On Windows Server 2022 the AES-SHA1 keys are aggregated into a single string.
    On Windows Server 2025+, the keys are called out individually.
#>

# AES-SHA1 on 2022-
$script:AES_SHA1_FILTER_2022 = "AES-SHA1"
#AES-SHA1 on 2025+
$script:AES_SHA1_FILTER_2025 = "SHA96"

enum AccountType {
    User
    Machine
    Service
}

class Account {
    hidden [long]$RecordId
    [string]$MachineName
    [datetime]$Time
    [string]$Name
    [AccountType]$Type
    [string]$Keys

    Account([long]$id, [string]$m, [datetime]$tc, [string]$name, [AccountType]$ct, [string]$ckeys) {
        $this.RecordId = $id
        $this.MachineName = $m
        $this.Time = $tc
        $this.Name = $name
        $this.Type = $ct
        $tmp = [System.Collections.ArrayList]::new()

        $ckeys.Split(",").Trim() | ForEach-Object {
            if ($_ -eq $script:AES_SHA1_FILTER_2022) {
                $tmp.Add("AES128-SHA96")
                $tmp.Add("AES256-SHA96")
            }
            else  {
                $tmp.Add($_)
            }
        }

        $this.Keys = $tmp -join '; ' # Using ; for CSV to be more CSV friendly
    }

    [string] GetEvtFilter() {
        return @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventRecordID=$($this.RecordId))]]</Select>
  </Query>
</QueryList>
"@
    }

    [System.Diagnostics.Eventing.Reader.EventLogRecord] ShowEvent() {
        $query = $this.GetEvtFilter()
        if ($this.MachineName.ToUpper() -eq "$ENV:COMPUTERNAME`.$ENV:USERDNSDOMAIN") {
            return Get-WinEvent -FilterXPath $query -LogName Security
        } else {
            return Get-WinEvent -FilterXPath $query -LogName Security -ComputerName $this.MachineName
        }
    }
}

#endregion

#region Globals

$script:XPathQuery = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4769) and (TimeCreated[@SystemTime >= '$($Since.ToString("yyyy-MM-ddTHH:mm:ss"))'])]]
    </Select>
  </Query>
  <Query Id="1" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4768) and (TimeCreated[@SystemTime >= '$($Since.ToString("yyyy-MM-ddTHH:mm:ss"))'])]]
    </Select>
  </Query>
</QueryList>
"@

<#
    The new properties counts are 21 for 4769 and 24 for 4668. Meaning if we have a lower
    property count then we are reading the old event data.
#>
$script:MIN_PROPERTY_COUNT = 21

$script:KeyFilter = ""
$script:NotKeyFilter = ""

#endregion

#region Functions

function Get-AccountsFromKDC {
    param(
        [string]$KDCName = $null,
        [string]$Query
    )
    Write-Debug "Query:`n$Query to KDC '$KDCName'"
    Write-Verbose "Attempting to query $KDCName"
    $Results = $null
    try {
        if ([string]::IsNullOrEmpty($KDCName)) {
            $Results = Get-WinEvent -FilterXPath $Query -LogName Security -ErrorAction Stop
        }
        else {
            $Results = Get-WinEvent -ComputerName $KDCName -FilterXPath $Query -LogName Security -ErrorAction Stop
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -eq "NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand") {
            $RealKdcName = if ($null -eq $KDCName) { "$ENV:COMPUTERNAME" } else { $KDCName }
            Write-Warning "No events found on $RealKdcName"
        }
        else {
            throw $_
        }
    }
    return $Results
}

function List-AccountKeys {
    [CmdletBinding()]
    param(
        [DateTime]$Since = $(Get-Date).AddDays(-30),
        [ValidateSet("DES", "RC4", "AES-SHA1", "All")]
        [string]$ContainsKeyType = "All",
        [ValidateSet("DES", "RC4", "AES-SHA1", "None")]
        [string]$NotContainsKeyType = "None",
        [ValidateSet("This", "AllKdcs")]
        [string]$SearchScope = "This"
    )

    if ("All" -ne $ContainsKeyType) {
        # translate AES-SHA1 into either
        if ("AES-SHA1" -eq $ContainsKeyType) {
            $script:KeyFilter = $script:AES_SHA1_FILTER
        }
        elseif ("DES" -eq $ContainsKeyType) {
            $script:KeyFilter = "DES"
        }
        else {
            $script:KeyFilter = $ContainsKeyType
        }
    }

    if ("None" -ne $NotContainsKeyType) {
        if ("AES-SHA1" -eq $NotContainsKeyType) {
            $script:NotKeyFilter = $script:AES_SHA1_FILTER
        }
        elseif ("DES" -eq $ContainsKeyType) {
            $script:NotKeyFilter = "DES"
        }
        else {
            $script:NotKeyFilter = $NotContainsKeyType
        }
    }

    $accounts = [System.Collections.ArrayList]::new()
    if ("This" -eq $SearchScope) {
        [Array]$LocalResult = $(Get-AccountsFromKDC -Query $script:XPathQuery)

        if ($null -ne $LocalResult -and 0 -ne $LocalResult.Count) {
            $accounts.AddRange($LocalResult)
        }
    }
    else {
        Get-ADDomainController -Filter * | ForEach-Object {
            $KDCName = $_.HostName

            try {
                [Array]$KdcResult = $(Get-AccountsFromKDC -KDCName $KDCName -Query $script:XPathQuery)

                if ($null -ne $KdcResult -and 0 -ne $KdcResult.Count) {
                    $accounts.AddRange($KdcResult)
                }
            }
            catch {
                Write-Error "Failed to get event logs from $KDCName with result: $_"
            }
        }
    }

    # Validate we are working with the correct version
    if ($accounts.Count -gt 0 -and $accounts[0].Properties.Count -lt $script:MIN_PROPERTY_COUNT) {
        Write-Error "Attempting to run script on Windows Version $([System.Environment]::OSVersion.Version) which doesn't have the new event metadata.
Please install the most recent Windows Updates available for this machine and attempt again."
        return
    }

    Write-Verbose "Accounts returned: $($accounts.Count)"

    $accounts | ForEach-Object {
        $KDC = $_.MachineName
        [string]$keys = $_.Properties[16].Value
        if (-not [string]::IsNullOrEmpty($script:NotKeyFilter)) {
            if ($keys.Contains($script:NotKeyFilter)) {
                continue
            }
        }

        if (-not [string]::IsNullOrEmpty($script:KeyFilter)) {
            if (-not $keys.Contains($script:KeyFilter)) {
                continue
            }
        }

        if (4769 -eq $_.Id) {
            $type = [AccountType]::Service
            $target = $_.Properties[2].Value
            if ($target.EndsWith("$")) {
                $type = [AccountType]::Machine
            }
            [Account]::new($_.RecordId, $KDC, $_.TimeCreated, $target, $type, $keys)
        }
        else {
            $target = $_.Properties[0].Value
            $type = if ($target.EndsWith("$")) {[AccountType]::Machine } else { [AccountType]::User }
            [Account]::new($_.RecordId, $KDC, $_.TimeCreated, $target, $type, $keys)
        }
    }
}

#endregion


if ($MyInvocation.InvocationName -ne ".") {
    List-AccountKeys @PSBoundParameters
}