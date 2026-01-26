class EncryptionType {
    [int]$Mask
    [int]$Value
    [string]$Name

    EncryptionType([int]$m, [int]$v, [string]$n) {
        $this.Mask = $m
        $this.Value = $v
        $this.Name = $n
    }

    [bool] EnabledInMask([int]$mask) {
        return ($mask -band $this.Mask) -eq $this.Mask
    }
}

$script:DES_CRC = [EncryptionType]::new(0x1, 1, "DES-CRC")
$script:DES_MD5 = [EncryptionType]::new(0x2, 3, "DES-MD5")
$script:RC4 = [EncryptionType]::new(0x4, -128, "RC4")
$script:AES128 = [EncryptionType]::new(0x8, 17, "AES128-SHA96")
$script:AES256 = [EncryptionType]::new(0x10, 18, "AES256-SHA96")
$script:AES_SK = [EncryptionType]::new(0x20, 18, "AES-SK")
$script:AES128_SHA2 = [EncryptionType]::new(0x40, 19, "AES128-SHA256")
$script:AES256_SHA2 = [EncryptionType]::new(0x80, 20, "AES256-SHA384")
$script:ETYPES = (
    $script:DES_CRC,
    $script:DES_MD5,
    $script:RC4,
    $script:AES128,
    $script:AES256,
    $script:AES_SK,
    $script:AES128_SHA2,
    $script:AES256_SHA2
)

class KerbRegDwordSetting {
    [string]$Name
    hidden [int]$Value
    hidden [int]$DefaultValue
    hidden [bool]$IsDefined
    hidden [scriptblock]$Callback
    hidden [string]$Key
    [string]$Setting

    hidden [void] Init($key, $name, $defaultValue, $callback) {
        $this.Name = $name
        $this.DefaultValue = $defaultValue
        $this.Callback = $callback
        $this.IsDefined = $false
        $this.Key = $key
        $this.Setting = ""
    }

    [void] Update() {
        try {
            $this.Value = Get-ItemPropertyValue -Path $this.Key -Name $this.Name -ErrorAction Stop
            $this.IsDefined = $true
        }
        catch {
            Write-Verbose "Exception while processing registry key $($this.Key) with value $($this.Name)`n$_)"
            $this.Value = $this.DefaultValue
            $this.IsDefined = $false
        }

        if ($null -ne $this.Callback) {
            $this.Setting = $this.Callback.Invoke($this.Value)
        }
        else {
            $this.Setting = $this.Value
        }
    }

    KerbRegDwordSetting($key, $name, $defaultValue, $callback) {
        $this.Init($key, $name, $defaultValue, $callback)
    }

    KerbRegDwordSetting($key, $name, $defaultValue) {
        $this.Init($key, $name, $defaultValue, $null)
    }

    [void] Set([int]$value) {
        $hex = "{0:X}" -f $value
        Write-Verbose "Setting $($this.Name) to $hex"
        if (-not $(Test-Path -Path $this.Key)) {
            New-Item -Path $this.Key -Force
        }
        Set-ItemProperty -Path $this.Key -Name $this.Name -Value $value -Type DWord
    }

    [void] Clear() {
        if ($null -ne $(Get-ItemProperty -Path $this.Key -Name $this.Name -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $this.Key -Name $this.Name
        }
    }

    [pscustomobject] Display([bool]$detailed) {
        $obj = [pscustomobject]@{
            Name    = $this.Name
            Setting = $this.Setting
        }

        if ($detailed) {
            Add-Member -InputObject $obj -Name "Value" -Value $this.Value -MemberType NoteProperty
            Add-Member -InputObject $obj -Name "DefaultValue" -Value $this.DefaultValue -MemberType NoteProperty
            Add-Member -InputObject $obj -Name "IsDefined" -Value $this.IsDefined -MemberType NoteProperty
            Add-Member -InputObject $obj -Name "IsDefault" -Value $($this.Value -eq $this.DefaultValue) -MemberType NoteProperty
        }

        return $obj
    }
}

# Format helpers

$script:FormatBoolean = [scriptblock]{
    if ($args -ne 0) {
        return "True"
    } else {
        return "False"
    }
}

$script:FormatSeconds = [scriptblock]{
    return "$args seconds"
}

$script:FormatMinutes = [scriptblock]{
    return "$args minutes"
}

$script:FormatBytes = [scriptblock]{
    return "$args bytes"
}

$script:FormatSET = [scriptblock]{
    param([int]$mask)
    $etypes_string = ""

    foreach ($etype in $script:ETYPES) {

        if ($etype.EnabledInMask($mask)) {
            if (-not [string]::IsNullOrEmpty($etypes_string)) {
                $etypes_string += ", "
            }
            $etypes_string += $etype.Name
        }
    }

    if ([string]::IsNullOrEmpty($etypes_string)) {
        $etypes_string = "None"
    }

    return $etypes_string.TrimEnd()
}

$script:FormatHex = [scriptblock]{
    return "0x{0:X}" -f $args
}