$NAMES_TO_VALUE = @{
    "SPN" = 0x1
    "PKINIT" = 0x2
    "ALL" = 0x4
    "S4U2Self" = 0x8
    "ETYPE" = 0x10
}

function Set-KdcConfig {
    <#
.SYNOPSIS
Set-KdcConfig adjust the configuration of a Windows Key Distribution Center (KDC)
.DESCRIPTION
Set-KdcConfig changes the current registry value of the Windows Key Distribution Center (KDC) to the specified value to change the behavior of the module.
.EXAMPLE
Set-KdcConfig -DefaultDomainSupportedEncTypes AES128-SHA96,AES256-SHA96 -KdcUseClientAddresses $false
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [bool]$KdcUseClientAddresses,
        [bool]$KdcDontCheckAddresses,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$NewConnectionTimeout,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$MaxDatagramReplySize,
        [ValidateSet("SPN", "PKINIT", "ALL", "S4U2Self", "ETYPE", "NONE")]
        [string[]]$KdcExtraLogLevel,
        [ValidateSet("RC4", "DES-CRC", "DES-MD5", "AES128-SHA96", "AES256-SHA96", "AES-SK")]
        [string[]]$DefaultDomainSupportedEncTypes
    )

    if (0 -eq $($PSBoundParameters.Keys | Where-Object { $script:KERBEROS_PARAMETER_MAPPING.Keys.Contains($_) }).Count) {
        throw "At least one of the defined parameters must be supplied"
    }


    $etypeConversion = @("DefaultDomainSupportedEncTypes")
    $boolConversion = @("KdcUseClientAddresses", "KdcDontCheckAddresses")
    $levelToMaskConversion = @("KdcExtraLogLevel")

    foreach ($parameter in $script:KDC_PARAMETER_MAP.Keys) {
        if ($PSBoundParameters.ContainsKey($parameter)) {
            Write-Verbose "Found matching key $($parameter)"

            $value = 0
            if ($PSCmdlet.ShouldProcess("KdcConfig $parameter set with value $($PSBoundParameters[$parameter])")) {
                if ($etypeConversion.Contains($parameter)) {

                    [int]$mask = 0
                    $values = $PSBoundParameters[$parameter]

                    $script:ETYPES | Where-Object { $values.Contains($_.Name) } | ForEach-Object {
                        $mask = $mask -bor $_.Mask
                    }

                    $value = $mask
                }
                elseif ($boolConversion.Contains($parameter)) {
                    $value = [int]$PSBoundParameters[$parameter]
                }
                elseif ($levelToMaskConversion.Contains($parameter)) {
                    $PSBoundParameters[$parameter] | ForEach-Object {
                        $value = $value -bor $NAMES_TO_VALUE[$_]
                    }
                }
                else {
                    $value = $PSBoundParameters[$parameter]
                }

                $script:KDC_PARAMETER_MAP[$parameter].Set($value)
            } else {
                Write-Verbose "Skipping the set of $parameter"
            }
        }
    }
}