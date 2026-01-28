<#
.SYNOPSIS
Retrieves ticket and session key encryption types
.DESCRIPTION
Searches the Security Event Log for instances of Event Id 4769 and Event Id 4768 to create a list of encryption types used in Kerberos tickets
.EXAMPLE
Get-KerbEncryptionUsage # This will list all requests seen in the the past 30 days
.EXAMPLE
Get-KerbEncryptionUsage -Encryption RC4 -EncryptionUsage Ticket # This will list all requests that used RC4 in the Ticket encryption
.EXAMPLE
Get-KerbEncryptionUsage -Searchscope AllKdcs -Since (Get-Date).AddDays(-7) # This will list all requests querying all KDCs for events in the past 7 days

.PARAMETER Encryption
Specifies the encryption type to be queried
.PARAMETER Since
Specifies the earliest point to be queried from
.PARAMETER SearchScope
Specifies whether the query should be the local machine or all KDCs
.PARAMETER EncryptionUsage
Specifies where to check for encryption usage. Ticket, SessionKey, Either or Both

.NOTES
Author: Will Aftring (wiaftrin)

When specifying AllKdcs, to pull the event log results remote Event Log reading must be enabled.

Copyright (c) Microsoft Corporation. All rights reserved.

#>

[CmdletBinding()]
param(
    [ValidateSet("RC4", "DES", "AES-SHA1", "AES128-SHA96", "AES256-SHA96", "All")]
    [string]$Encryption = "All",
    [DateTime]$Since = $(Get-Date).AddDays(-30),
    [ValidateSet("This", "AllKdcs")]
    [string]$SearchScope = "This",
    [ValidateSet("Ticket", "SessionKey", "Either", "Both")]
    [string]$EncryptionUsage = "Either"
)

#region Classes
class EncryptionType {
    [string]$Name
    [int]$Value
    EncryptionType([string]$name, [int]$value) {
        $this.Name = $name
        $this.Value = $value
    }
    [string]ToDataString() {
        return "Data='0x{0:x}'" -f $this.Value
    }

    [string]ToString() {
        return $this.Name
    }

    [bool]Equals([object]$other) {
        if ($null -eq $other -or $this.GetType() -ne $other.GetType()) {
            return $false
        }
        $EType = [EncryptionType]$other
        return $EType.Name -eq $this.Name -and $EType.Value -eq $this.Value
    }
}

enum RequestType {
    AS
    TGS
}

class KerbRequest {
    hidden [long]$RecordId
    [string]$MachineName
    [DateTime]$Time
    [string]$Requestor
    [string]$Source
    [string]$Target
    [RequestType]$Type
    [EncryptionType]$Ticket
    [EncryptionType]$SessionKey

    KerbRequest([long]$id, [string]$m, [datetime]$tc, [string]$r, [string]$s, [string]$t, [RequestType]$rt, [EncryptionType]$te, [EncryptionType]$se) {
        $this.RecordId = $id
        $this.MachineName = $m
        $this.Time = $tc
        if ($r.StartsWith("::ffff:")) {
            $r = $r.Replace("::ffff:", "")
        }
        $this.Requestor = $r
        $this.Source = $s
        $this.Target = $t
        $this.Type = $rt
        $this.Ticket = $te
        $this.SessionKey = $se
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

$script:DES_CRC = [EncryptionType]::new("DES-CRC", 0x1)
$script:DES_MD5 = [EncryptionType]::new("DES-MD5", 0x3)
$script:RC4 = [EncryptionType]::new("RC4", 0x17)
$script:AES128 = [EncryptionType]::new("AES128-SHA96", 0x11)
$script:AES256 = [EncryptionType]::new("AES256-SHA96", 0x12)
$script:AES128_SHA256 = [EncryptionType]::new("AES128-SHA256", 0x13)
$script:AES256_SHA384 = [EncryptionType]::new("AES256-SHA384", 0x14)
$script:UnknownEType = [EncryptionType]::new("Unknown", 0xFF)

$script:EncryptionTypes = @(
    $script:DES_CRC
    $script:DES_MD5
    $script:RC4
    $script:AES128
    $script:AES256
    $script:AES128_SHA256
    $script:AES256_SHA384
    $script:UnknownEType
)

<#
    The new properties counts are 21 for 4769 and 24 for 4668. Meaning if we have a lower
    property count then we are reading the old event data.
#>
$script:MIN_PROPERTY_COUNT = 21

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

#endregion

#region Functions
function Get-KdcEventLog {
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

    Write-Debug "$Results"
    return $Results
}

function Check-ETypeUsage {
    param(
        [string]$UsageMode,
        [EncryptionType]$TicketEtype,
        [EncryptionType]$SKEtype,
        [EncryptionType]$SearchEtype
    )

    if ("Both" -eq $EncryptionUsage) {
        return $($TicketEtype -eq $SKEtype -and $SearchEtype -eq $TicketEtype)
    }
    elseif ("Ticket" -eq $EncryptionUsage) {
        return $($TicketEtype -eq $SearchEtype)
    }
    elseif ("SessionKey" -eq $EncryptionUsage) {
        return $($SKEtype -eq $SearchEtype)
    }
    else {
        return $($SKEtype -eq $SearchEtype -or $TicketEtype -eq $SearchEtype)
    }
}

function Get-EncryptionType {
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "Name")]
        [string]$Name,
        [Parameter(Mandatory = $true, ParameterSetName = "Value")]
        [int]$Value
    )

    foreach ($etype in $script:EncryptionTypes) {
        if (($PSCmdlet.ParameterSetName -eq "Name" -and $etype.Name -eq $Name) `
                -or ($PSCmdlet.ParameterSetName -eq "Value" -and $etype.Value -eq $Value)) {
            return $etype
        }
    }

    return $script:UnknownEType
}

function Get-EncryptionTypes {
    return $script:EncryptionTypes
}


function Get-KerbEncryptionUsage {
    [CmdletBinding()]
    param(
        [ValidateSet("RC4", "DES", "AES-SHA1", "AES128-SHA96", "AES256-SHA96", "All")]
        [string]$Encryption = "All",
        [DateTime]$Since = $(Get-Date).AddDays(-30),
        [ValidateSet("This", "AllKdcs")]
        [string]$SearchScope = "This",
        [ValidateSet("Ticket", "SessionKey", "Either", "Both")]
        [string]$EncryptionUsage = "Either"
    )


    $Events = [System.Collections.ArrayList]::new()
    if ("AllKdcs" -eq $SearchScope) {

        Get-ADDomainController -Filter * | ForEach-Object {
            $KDCName = $_.HostName
            try {
                [Array]$KdcResult = $(Get-KdcEventLog -KDCName $KDCName -Query $script:XPathQuery)

                if ($null -ne $KdcResult -and 0 -ne $KdcResult.Count) {
                    $Events.AddRange($KdcResult)
                }
            }
            catch {
                Write-Error "Failed to get event logs from $KDCName with result: $_"
            }
        }
    }
    else {
        try {
            [Array]$LocalResult = $(Get-KdcEventLog -Query $script:XPathQuery)

            if ($null -ne $LocalResult -and 0 -ne $LocalResult.Count) {
                $Events.AddRange($LocalResult)
            }
        }
        catch {
            Write-Error "Failed to get event logs from $KDCName with result: $_"
        }
    }

    # Validate we are working with the correct version
    if ($accounts.Count -gt 0 -and $accounts[0].Properties.Count -lt $script:MIN_PROPERTY_COUNT) {
        Write-Error "Attempting to run script on Windows Version $([System.Environment]::OSVersion.Version) which doesn't have the new event metadata.
Please install the most recent Windows Updates available for this machine and attempt again."
        return
    }


    Write-Verbose "Total events: $($Events.Count)"
    $Events | ForEach-Object {
        $ShowRequest = $true
        $T = $null
        $SK = $null
        $R = $null
        $Target = $null
        $IP = $null

        if ($_.Id -eq 4769) {
            $Target = $_.Properties[2].Value
            $T = Get-EncryptionType -Value $_.Properties[5].Value
            $SK = Get-EncryptionType -Value $_.Properties[20].Value
            $R = [RequestType]::TGS
            $IP = $_.Properties[6].Value
        }
        else {
            $Target = $_.Properties[3].Value
            $T = Get-EncryptionType -Value $_.Properties[7].Value
            $SK = Get-EncryptionType -Value $_.Properties[22].Value
            $R = [RequestType]::AS
            $IP = $_.Properties[9].Value
        }

        if ("DES" -eq $Encryption) {
            $D1 = Check-ETypeUsage -UsageMode $EncryptionUsage -TicketEtype $T -SKEtype $SK -SearchEtype $script:DES_CRC
            $D2 = Check-ETypeUsage -UsageMode $EncryptionUsage -TicketEtype $T -SKEtype $SK -SearchEtype $script:DES_MD5
            $ShowRequest = $D1 -or $D2
        }
        elseif ("AES-SHA1" -eq $Encryption) {
            $A1 = Check-ETypeUsage -UsageMode $EncryptionUsage -TicketEtype $T -SKEtype $SK -SearchEtype $script:AES128
            $A2 = Check-ETypeUsage -UsageMode $EncryptionUsage -TicketEtype $T -SKEtype $SK -SearchEtype $script:AES256
            $ShowRequest = $A1 -or $A2
        }
        elseif ("All" -ne $Encryption) {
            $Etype = Get-EncryptionType -Name $Encryption
            $ShowRequest = $(Check-ETypeUsage -UsageMode $EncryptionUsage -TicketEtype $T -SKEtype $SK -SearchEtype $EType)
        }

        if ($ShowRequest) {
            [KerbRequest]::new($_.RecordId, $_.MachineName, $_.TimeCreated, $IP, $_.Properties[0].Value, $Target, $R, $T, $SK)
        }
    }
}

#endregion

if ($MyInvocation.InvocationName -ne ".") {
    Get-KerbEncryptionUsage @PSBoundParameters
}

#endregion