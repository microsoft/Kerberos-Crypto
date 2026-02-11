function Get-KerbConfig {
    <#
.SYNOPSIS
Get-KerbConfig displays the current Windows Kerberos client registry based configurations.
.DESCRIPTION
Get-KerbConfig reads the current registry values for the Windows Kerberos client to determine what the state of the Kerberos client is.
These configurations are based around the publicly documented keys here: https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-protocol-registry-kdc-configuration-keys
.PARAMETER Configurations
A list of configuration names to be displayed. Otherwise, all configurations will be displayed.
.PARAMETER Detailed
Display the current unparsed setting along with if the configuration has been adjusted from the default value.
.EXAMPLE
Get-KerbConfig

Name                     Setting
----                     -------
SupportedEncryptionTypes RC4, AES128-SHA96, AES256-SHA96
SkewTime                 5 minutes
LogLevel                 0
MaxPacketSize            1465 bytes
StartupTime              120 seconds
KdcWaitTime              10 seconds
KdcBackoffTime           10 seconds
KdcSendRetries           3
DefaultEncryptionType    AES256-SHA96
FarKdcTimeout            10 minutes
NearKdcTimeout           30 minutes
StronglyEncryptDatagram  1
MaxReferralCount         6
MaxTokenSize             48000
SpnCacheTimeout          15 minutes
S4UCacheTimeout          15 minutes
S4UTicketLifetime        15 minutes
RetryPdc                 False
RequestOptions           0x10000
ClientIpAddresses        False
TgtRenewalTime           600 seconds
AllowTgtSessionKey       False
.EXAMPLE
Get-KerbConfig -Detailed

Name                     Setting                         Value DefaultValue IsDefined IsDefault
----                     -------                         ----- ------------ --------- ---------
SupportedEncryptionTypes RC4, AES128-SHA96, AES256-SHA96    28           28     False      True
SkewTime                 5 minutes                           5            5     False      True
LogLevel                 0                                   0            0     False      True
MaxPacketSize            1465 bytes                       1465         1465     False      True
StartupTime              120 seconds                       120          120     False      True
KdcWaitTime              10 seconds                         10           10     False      True
KdcBackoffTime           10 seconds                         10           10     False      True
KdcSendRetries           3                                   3            3     False      True
DefaultEncryptionType    AES256-SHA96                       18           18     False      True
FarKdcTimeout            10 minutes                         10           10     False      True
NearKdcTimeout           30 minutes                         30           30     False      True
StronglyEncryptDatagram  1                                   1            1     False      True
MaxReferralCount         6                                   6            6     False      True
MaxTokenSize             48000                           48000        48000     False      True
SpnCacheTimeout          15 minutes                         15           15     False      True
S4UCacheTimeout          15 minutes                         15           15     False      True
S4UTicketLifetime        15 minutes                         15           15     False      True
RetryPdc                 False                               0            0     False      True
RequestOptions           0x10000                         65536        65536     False      True
ClientIpAddresses        False                               0            0     False      True
TgtRenewalTime           600 seconds                       600          600     False      True
AllowTgtSessionKey       False                               0            0     False      True
#>
    [CmdletBinding(DefaultParameterSetName = "All")]
    param(
        [Parameter(ValueFromPipeline, ParameterSetName = "Configurations", Mandatory)]
        [ValidateSet(
            "SupportedEncryptionTypes", "SkewTime", "LogLevel", "MaxPacketSize", "StartupTime",
            "KdcWaitTime", "KdcBackoffTime", "KdcSendRetries", "DefaultEncryptionType",
            "FarKdcTimeout", "NearKdcTimeout", "StronglyEncryptDatagram", "MaxReferralCount",
            "MaxTokenSize", "SpnCacheTimeout", "S4UTicketLifetime", "RetryPdc", "RequestOptions",
            "ClientIpAddresses", "TgtRenewalTime", "AllowTgtSessionKey")]
        [string[]]$Configurations,

        [Parameter(ParameterSetName = "All")]
        [switch]$All,

        [Parameter()]
        [switch]$Detailed
    )

    begin {
        $originalPreference = $null
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"]) {
            $originalPreference = $VerbosePreference
            $VerbosePreference = 'Continue'
        }
    }

    process {
        $selectedKeys = if ($PSCmdlet.ParameterSetName -eq "All") {
            $script:KERBEROS_KEYS
        }
        else {
            $script:KERBEROS_KEYS | Where-Object { $Configurations.Contains($_.Name) }
        }

        $selectedKeys | ForEach-Object {
            $_.Update()
            $_.Display($Detailed)
        }

    }

    end {
        if ($null -ne $originalPreference) {
            $VerbosePreference = $originalPreference
        }
    }
}
