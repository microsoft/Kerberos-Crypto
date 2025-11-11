function Clear-KerbConfig {
<#
.SYNOPSIS
Clear-KerbConfig clears the selected Microsoft Windows Kerberos configuration value.
.DESCRIPTION
Clear-KerbConfig clears the backing registry value for the selected configuration.
.EXAMPLE
Clear-KerbConfig -SupportedEncryptionTypes
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [switch]$SupportedEncryptionTypes,
        [switch]$SkewTimeInMinutes,
        [switch]$LogLevel,
        [switch]$MaxPacketSize,
        [switch]$StartupTimeInSeconds,
        [switch]$KdcWaitTimeInSeconds,
        [switch]$KdcBackoffTimeInSeconds,
        [switch]$KdcSendRetries,
        [switch]$DefaultEncryptionType,
        [switch]$FarKdcTimeoutInMinutes,
        [switch]$NearKdcTimeoutInMinutes,
        [switch]$StronglyEncryptDatagram,
        [switch]$MaxReferralCount,
        [switch]$MaxTokenSize,
        [switch]$SpnCacheTimeoutInMinutes,
        [switch]$S4UCacheTimeoutInMinutes,
        [switch]$S4UTicketLifetimeInMinutes,
        [switch]$ShouldRetryPdc,
        [switch]$RequestOptions,
        [switch]$EnableClientIpAddresses,
        [switch]$TgtRenewalTimeInSeconds,
        [switch]$AllowTgtSessionKey,
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
        foreach($parameter in $script:KERBEROS_PARAMETER_MAPPING.Keys) {
            if ($All -or $PSBoundParameters.ContainsKey($parameter)) {
                Write-Verbose "Clearing configuration for $parameter"
                if ($PSCmdlet.ShouldProcess("KerbConfig '$parameter'")) {
                    $script:KERBEROS_PARAMETER_MAPPING[$parameter].Clear()
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