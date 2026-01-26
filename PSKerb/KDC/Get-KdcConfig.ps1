function Get-KdcConfig {
<#
.SYNOPSIS
Get-KdcConfig displays the current Windows Key Distribution Center (KDC) registry based configurations
.DESCRIPTION
Get-KDCConfig reads the current registry values for the Windows Key Distribution Center (KDC) to determine what the state of the KDC is.
These configurations are based around the publicly documented keys here: https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-protocol-registry-kdc-configuration-keys
.PARAMETER Configurations
A list of configuration names to be displayed. Otherwise, all configurations will be displayed.
.PARAMETER Detailed
Display the current unparsed setting along with if the configuration has been adjusted from the default value.

.EXAMPLE
Get-KdcConfig

Name                           Setting
----                           -------
KdcUseClientAddresses          False
KdcDontCheckAddresses          True
NewConnectionTimeout           10 seconds
MaxDatagramReplySize           1465 bytes
KdcExtraLogLevel               PKINIT
DefaultDomainSupportedEncTypes None

.EXAMPLE
Get-KdcConfig -Detailed

Name         : KdcUseClientAddresses
Setting      : False
Value        : 0
DefaultValue : 0
IsDefined    : False
IsDefault    : True

Name         : KdcDontCheckAddresses
Setting      : True
Value        : 1
DefaultValue : 1
IsDefined    : False
IsDefault    : True

Name         : NewConnectionTimeout
Setting      : 10 seconds
Value        : 10
DefaultValue : 10
IsDefined    : False
IsDefault    : True

Name         : MaxDatagramReplySize
Setting      : 1465 bytes
Value        : 1465
DefaultValue : 1465
IsDefined    : False
IsDefault    : True

Name         : KdcExtraLogLevel
Setting      : PKINIT
Value        : 2
DefaultValue : 2
IsDefined    : False
IsDefault    : True

Name         : DefaultDomainSupportedEncTypes
Setting      : None
Value        : 0
DefaultValue : 0
IsDefined    : False
IsDefault    : True
#>

    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        [Parameter(ValueFromPipeline, ParameterSetName = "Configurations", Mandatory)]
        [ValidateSet("KdcUseClientAddresses", "KdcDontCheckAddresses", "NewConnectionTimeout",
            "MaxDatagramReplySize", "KdcExtraLogLevel", "DefaultDomainSupportedEncTypes")]
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
            $script:KDC_KEYS
        }
        else {
            $script:KDC_KEYS | Where-Object { $Configurations.Contains($_.Name) }
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