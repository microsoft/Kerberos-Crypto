$script:KDC_KEY_PATH = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KDC"
$script:DDSET_KEY_PATH = "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

$script:KDC_LOG_LEVEL_SPN = 0x1
$script:KDC_LOG_LEVEL_PKINIT = 0x2
$script:KDC_LOG_LEVEL_ALL = 0x4
$script:KDC_LOG_LEVEL_S4U = 0x8
$script:KDC_LOG_LEVEL_ETYPE = 0x10


$script:KDC_KEYS_KDCUSECLIENTADDRESSES = [KerbRegDwordSetting]::new($script:KDC_KEY_PATH, "KdcUseClientAddresses", 0, $script:FormatBoolean)
$script:KDC_KEYS_KDCDONTCHECKADDRESSES = [KerbRegDwordSetting]::new($script:KDC_KEY_PATH, "KdcDontCheckAddresses", 1, $script:FormatBoolean)
$script:KDC_KEYS_NEWCONNECTIONTIMEOUT = [KerbRegDwordSetting]::new($script:KDC_KEY_PATH, "NewConnectionTimeout", 10, $script:FormatSeconds)
$script:KDC_KEYS_MAXDATAGRAMREPLYSIZE = [KerbRegDwordSetting]::new($script:KDC_KEY_PATH, "MaxDatagramReplySize", 1465, $script:FormatBytes)
$script:KDC_KEYS_KDCEXTRALOGLEVEL = [KerbRegDwordSetting]::new($script:KDC_KEY_PATH, "KdcExtraLogLevel", 2, {
    param(
        [int]$value
    )
    $level = ""

    if (($value -band $script:KDC_LOG_LEVEL_SPN) -eq $script:KDC_LOG_LEVEL_SPN) {
        $level += "SPN "
    }
    if (($value -band $script:KDC_LOG_LEVEL_PKINIT) -eq $script:KDC_LOG_LEVEL_PKINIT) {
        $level += "PKINIT "
    }
    if (($value -band $script:KDC_LOG_LEVEL_ALL) -eq $script:KDC_LOG_LEVEL_ALL) {
        $level += "ALL "
    }
    if (($value -band $script:KDC_LOG_LEVEL_S4U) -eq $script:KDC_LOG_LEVEL_S4U) {
        $level += "S4U2Self "
    }
    if (($value -band $script:KDC_LOG_LEVEL_ETYPE) -eq $script:KDC_LOG_LEVEL_ETYPE) {
        $level += "ETYPE"
    }

    if ([string]::IsNullOrEmpty($level)) {
        $level = "NONE"
    }

    return $level.Trim()
})

$script:KDC_KEYS_DEFAULTDOMAINSUPPORTEDENCTYPES = [KerbRegDwordSetting]::new($script:DDSET_KEY_PATH, "DefaultDomainSupportedEncTypes", 0x24, $script:FormatSET)

$script:KDC_KEYS = @(
    $script:KDC_KEYS_KDCUSECLIENTADDRESSES,
    $script:KDC_KEYS_KDCDONTCHECKADDRESSES,
    $script:KDC_KEYS_NEWCONNECTIONTIMEOUT,
    $script:KDC_KEYS_MAXDATAGRAMREPLYSIZE,
    $script:KDC_KEYS_KDCEXTRALOGLEVEL,
    $script:KDC_KEYS_DEFAULTDOMAINSUPPORTEDENCTYPES
)

$script:KDC_PARAMETER_MAP = @{
    "KdcUseClientAddresses" = $script:KDC_KEYS_KDCUSECLIENTADDRESSES
    "KdcDontCheckAddresses" = $script:KDC_KEYS_KDCDONTCHECKADDRESSES
    "NewConnectionTimeout" = $script:KDC_KEYS_NEWCONNECTIONTIMEOUT
    "MaxDatagramReplySize" = $script:KDC_KEYS_MAXDATAGRAMREPLYSIZE
    "KdcExtraLogLevel" = $script:KDC_KEYS_KDCEXTRALOGLEVEL
    "DefaultDomainSupportedEncTypes" = $script:KDC_KEYS_DEFAULTDOMAINSUPPORTEDENCTYPES
}