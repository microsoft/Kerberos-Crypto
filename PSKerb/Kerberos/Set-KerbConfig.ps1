function Set-KerbConfig {
    <#
.SYNOPSIS
Set-KerbConfig adjust the configuration of a Windows Kerberos client registry based configuration
.DESCRIPTION
Set-KerbConfig changes the current registry value of the Windows Kerberos Client to the specified value to change the behavior of the module.
.EXAMPLE
Set-KerbConfig -SupportedEncryptionTypes AES128-SHA96,AES256-SHA96 -FarKdcTimeoutInMinutes 10
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter()]
        [ValidateSet("RC4", "DES-CRC", "DES-MD5", "AES128-SHA96", "AES256-SHA96")]
        [string[]]$SupportedEncryptionTypes,
        [ValidateSet(0, [int]::MaxValue)]
        [int]$SkewTimeInMinutes,
        [ValidateRange(0, 5)]
        [int]$LogLevel,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$MaxPacketSize,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$StartupTimeInSeconds,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$KdcWaitTimeInSeconds,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$KdcBackoffTimeInSeconds,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$KdcSendRetries,
        [ValidateSet("RC4", "DES-CRC", "DES-MD5", "AES128-SHA96", "AES256-SHA96")]
        [string[]]$DefaultEncryptionType,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$FarKdcTimeoutInMinutes,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$NearKdcTimeoutInMinutes,
        [bool]$StronglyEncryptDatagram,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$MaxReferralCount,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$MaxTokenSize,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$SpnCacheTimeoutInMinutes,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$S4UCacheTimeoutInMinutes,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$S4UTicketLifetimeInMinutes,
        [bool]$ShouldRetryPdc,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$RequestOptions,
        [bool]$EnableClientIpAddresses,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$TgtRenewalTimeInSeconds,
        [bool]$AllowTgtSessionKey
    )

    if (0 -eq $($PSBoundParameters.Keys | Where-Object { $script:KERBEROS_PARAMETER_MAPPING.Keys.Contains($_) }).Count) {
        throw "At least one of the defined parameters must be supplied"
    }


    $etypeConversion = @("SupportedEncryptionTypes", "DefaultEncryptionType")
    $boolConversion = @("StronglyEncryptDatagram", "ShouldRetryPdc", "AllowTgtSessionKey")

    foreach ($parameter in $script:KERBEROS_PARAMETER_MAPPING.Keys) {
        if ($PSBoundParameters.ContainsKey($parameter)) {
            Write-Verbose "Found matching key $($parameter)"

            $value = 0
            if ($PSCmdlet.ShouldProcess("KerbConfig $parameter set with value $($PSBoundParameters[$parameter])")) {
                if ($etypeConversion.Contains($parameter)) {

                    [int]$mask = 0
                    $values = $PSBoundParameters[$parameter]

                    $script:ETYPES| Where-Object { $values.Contains($_.Name) } | ForEach-Object {
                        $mask = $mask -bor $_.Mask
                    }

                    $value = $mask
                }
                elseif ($boolConversion.Contains($parameter)) {
                    $value = [int]$PSBoundParameters[$parameter]
                }
                else {
                    $value = $PSBoundParameters[$parameter]
                }

                $script:KERBEROS_PARAMETER_MAPPING[$parameter].Set($value)
            } else {
                Write-Verbose "Skipping the set of $parameter"
            }
        }
    }
}