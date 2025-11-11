
$script:KERBEROS_KEY_PATH = "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

$script:KERBEROS_KEYS_SET = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "SupportedEncryptionTypes", 0x1c, $script:FormatSET)
$script:KERBEROS_KEYS_SKEWTIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "SkewTime", 5, $script:FormatMinutes)
$script:KERBEROS_KEYS_LOGLEVEL = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "LogLevel", 0)
$script:KERBEROS_KEYS_MAXPACKETSIZE = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "MaxPacketSize", 1465, $script:FormatBytes)
$script:KERBEROS_KEYS_STARTUPTIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "StartupTime", 120, $script:FormatSeconds)
$script:KERBEROS_KEYS_KDCWAITTIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "KdcWaitTime", 10, $script:FormatSeconds)
$script:KERBEROS_KEYS_KDCBACKOFFTIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "KdcBackoffTime", 10, $script:FormatSeconds)
$script:KERBEROS_KEYS_KDCSENDRETRIES = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "KdcSendRetries", 3)
$script:KERBEROS_KEYS_DEFAULTENCRYPTIONTYPE = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "DefaultEncryptionType", 18, {
        param([int]$value)
        foreach ($etype in $local:ETYPES) {
            if ($etype.Value -eq $value) {
                return $etype.Name
            }
        }
        return "None"
    })
$script:KERBEROS_KEYS_FARKDCTIMEOUT = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "FarKdcTimeout", 10, $script:FormatMinutes)
$script:KERBEROS_KEYS_NEARKDCTIMEOUT = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "NearKdcTimeout", 30, $script:FormatMinutes)
$script:KERBEROS_KEYS_STRONGLYENCRYPTDATAGRAM = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "StronglyEncryptDatagram", 1, { return $args -eq 1 })
$script:KERBEROS_KEYS_MAXREFERRALCOUNT = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "MaxReferralCount", 6)
$script:KERBEROS_KEYS_MAXTOKENSIZE = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "MaxTokenSize", 48000)
$script:KERBEROS_KEYS_SPNCACHETIMEOUT = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "SpnCacheTimeout", 15, $script:FormatMinutes)
$script:KERBEROS_KEYS_S4UCACHETIMEOUT = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "S4UCacheTimeout", 15, $script:FormatMinutes)
$script:KERBEROS_KEYS_S4UTICKETLIFETIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "S4UTicketLifetime", 15, $script:FormatMinutes)
$script:KERBEROS_KEYS_RETRYPDC = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "RetryPdc", 0, $script:FormatBoolean)
$script:KERBEROS_KEYS_REQUESTOPTIONS = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "RequestOptions", 0x00010000, $script:FormatHex)
$script:KERBEROS_KEYS_CLIENTIPADDRESSES = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "ClientIpAddresses", 0, $script:FormatBoolean)
$script:KERBEROS_KEYS_TGTRENEWALTIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "TgtRenewalTime", 600, $script:FormatSeconds)
$script:KERBEROS_KEYS_ALLOWTGTSESSIONKEY = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "AllowTgtSessionKey", 0, $script:FormatBoolean)
$script:KERBEROS_KEYS = (
    $script:KERBEROS_KEYS_SET,
    $script:KERBEROS_KEYS_SKEWTIME,
    $script:KERBEROS_KEYS_LOGLEVEL,
    $script:KERBEROS_KEYS_MAXPACKETSIZE,
    $script:KERBEROS_KEYS_STARTUPTIME,
    $script:KERBEROS_KEYS_KDCWAITTIME,
    $script:KERBEROS_KEYS_KDCBACKOFFTIME,
    $script:KERBEROS_KEYS_KDCSENDRETRIES,
    $script:KERBEROS_KEYS_DEFAULTENCRYPTIONTYPE,
    $script:KERBEROS_KEYS_FARKDCTIMEOUT,
    $script:KERBEROS_KEYS_NEARKDCTIMEOUT,
    $script:KERBEROS_KEYS_STRONGLYENCRYPTDATAGRAM,
    $script:KERBEROS_KEYS_MAXREFERRALCOUNT,
    $script:KERBEROS_KEYS_MAXTOKENSIZE,
    $script:KERBEROS_KEYS_SPNCACHETIMEOUT,
    $script:KERBEROS_KEYS_S4UCACHETIMEOUT,
    $script:KERBEROS_KEYS_S4UTICKETLIFETIME,
    $script:KERBEROS_KEYS_RETRYPDC,
    $script:KERBEROS_KEYS_REQUESTOPTIONS,
    $script:KERBEROS_KEYS_CLIENTIPADDRESSES,
    $script:KERBEROS_KEYS_TGTRENEWALTIME,
    $script:KERBEROS_KEYS_ALLOWTGTSESSIONKEY
)

$script:KERBEROS_PARAMETER_MAPPING = @{
    "SupportedEncryptionTypes"   = $script:KERBEROS_KEYS_SET
    "SkewTimeInMinutes"          = $script:KERBEROS_KEYS_SKEWTIME
    "LogLevel"                   = $script:KERBEROS_KEYS_LOGLEVEL
    "MaxPacketSize"              = $script:KERBEROS_KEYS_MAXPACKETSIZE
    "StartupTimeInSeconds"       = $script:KERBEROS_KEYS_STARTUPTIME
    "KdcWaitTimeInSeconds"       = $script:KERBEROS_KEYS_KDCWAITTIME
    "KdcBackoffTimeInSeconds"    = $script:KERBEROS_KEYS_KDCBACKOFFTIME
    "KdcSendRetries"             = $script:KERBEROS_KEYS_KDCSENDRETRIES
    "DefaultEncryptionType"      = $script:KERBEROS_KEYS_DEFAULTENCRYPTIONTYPE
    "FarKdcTimeoutInMinutes"     = $script:KERBEROS_KEYS_FARKDCTIMEOUT
    "NearKdcTimeoutInMinutes"    = $script:KERBEROS_KEYS_NEARKDCTIMEOUT
    "StronglyEncryptDatagram"    = $script:KERBEROS_KEYS_STRONGLYENCRYPTDATAGRAM
    "MaxReferralCount"           = $script:KERBEROS_KEYS_MAXREFERRALCOUNT
    "MaxTokenSize"               = $script:KERBEROS_KEYS_MAXTOKENSIZE
    "SpnCacheTimeoutInMinutes"   = $script:KERBEROS_KEYS_SPNCACHETIMEOUT
    "S4UCacheTimeoutInMinutes"   = $script:KERBEROS_KEYS_S4UCACHETIMEOUT
    "S4UTicketLifetimeInMinutes" = $script:KERBEROS_KEYS_S4UTICKETLIFETIME
    "ShouldRetryPdc"             = $script:KERBEROS_KEYS_RETRYPDC
    "RequestOptions"             = $script:KERBEROS_KEYS_REQUESTOPTIONS
    "EnableClientIpAddresses"    = $script:KERBEROS_KEYS_CLIENTIPADDRESSES
    "TgtRenewalTimeInSeconds"    = $script:KERBEROS_KEYS_TGTRENEWALTIME
    "AllowTgtSessionKey"         = $script:KERBEROS_KEYS_ALLOWTGTSESSIONKEY
}

#endregion


