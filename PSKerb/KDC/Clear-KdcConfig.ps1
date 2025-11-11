function Clear-KdcConfig {
<#
.SYNOPSIS
Clear-KdcConfig clears the selected Microsoft Windows Key Distribution Center (KDC) configuration value.
.DESCRIPTION
Clear-KdcConfig clears the backing registry value for the selected configuration.
.EXAMPLE
Clear-KdcConfig -SupportedEncryptionTypes
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [switch]$KdcUseClientAddresses,
        [switch]$KdcDontCheckAddresses,
        [switch]$NewConnectionTimeout,
        [switch]$MaxDatagramReplySize,
        [switch]$KdcExtraLogLevel,
        [switch]$DefaultDomainSupportedEncTypes,
        [switch]$All
    )

    begin {
        if (0 -eq $PSBoundParameters.Count) {
            throw "At least one of the defined parameters must be supplied"
        }

        $oldImpact = $ConfirmPreference
        if ($All) {
            $ConfirmPreference = 'High'
        }
    }

    process {
        foreach($parameter in $script:KDC_PARAMETER_MAP.Keys) {
            if ($All -or $PSBoundParameters.ContainsKey($parameter)) {
                Write-Verbose "Clearing configuration for $parameter"
                if ($PSCmdlet.ShouldProcess("KdcConfig '$parameter'")) {
                    $script:KDC_PARAMETER_MAP[$parameter].Clear()
                } else {
                    Write-Verbose "Skipping clearing $parameter"
                }
            }
        }
    }

    end {
        if ($oldImpact -ne $ConfirmPreference) {
            $ConfirmPreference = $oldImpact
        }
    }

}