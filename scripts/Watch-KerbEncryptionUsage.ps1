<#
.SYNOPSIS
Actively monitors Kerberos ticket and session key encryption usage in real time.
.DESCRIPTION
Subscribes to the Security event log and emits a KerbRequest object every time
a 4768 (AS-REQ) or 4769 (TGS-REQ) event is written that matches the requested
encryption / usage filter. Press Ctrl+C to stop watching.

On first run the script checks whether Kerberos failure auditing is enabled and
offers to turn it on via auditpol.exe (requires elevation). Use the
-DisableFailureAuditing switch to revert that change later.
.EXAMPLE
Watch-KerbEncryptionUsage
.EXAMPLE
Watch-KerbEncryptionUsage -Encryption RC4 -EncryptionUsage Ticket
.EXAMPLE
Watch-KerbEncryptionUsage -Encryption DES -EncryptionUsage Either
.EXAMPLE
Watch-KerbEncryptionUsage -DisableFailureAuditing

.PARAMETER Encryption
Specifies the encryption type to monitor.
Valid values: RC4, DES, AES-SHA1, AES128-SHA96, AES256-SHA96, All.
Default is All.
.PARAMETER EncryptionUsage
Specifies where to check for the encryption type.
Valid values: Ticket, SessionKey, Either, Both.
Default is Either.
.PARAMETER DisableFailureAuditing
When specified, disables Kerberos failure auditing for the relevant subcategories
via auditpol.exe and exits. No event monitoring is performed.

.NOTES
Author: Will Aftring (wiaftrin)

This script is experimental and subject to breaking changes.

Requires permission to read the Security event log (typically administrator).

Copyright (c) Microsoft Corporation. All rights reserved.
#>

[CmdletBinding()]
param(
    [ValidateSet("RC4", "DES", "AES-SHA1", "AES128-SHA96", "AES256-SHA96", "All")]
    [string]$Encryption = "All",
    [ValidateSet("Ticket", "SessionKey", "Either", "Both")]
    [string]$EncryptionUsage = "Either",
    [switch]$DisableFailureAuditing
)

if ($psISE) {
    Write-Error "Running this script in PowerShell ISE is not supported."
    return
}

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
    [DateTime]$Time
    [string]$Requestor
    [string]$Source
    [string]$Target
    [RequestType]$Type
    [EncryptionType]$Ticket
    [EncryptionType]$SessionKey
    [uint32]$Status

    KerbRequest([long]$id, [datetime]$tc, [string]$r, [string]$s, [string]$t, [RequestType]$rt, [EncryptionType]$te, [EncryptionType]$se, [uint32]$status) {
        $this.RecordId = $id
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
        $this.Status = $status
    }

    [bool] IsSuccess() {
        return $this.Status -eq 0
    }
}
#endregion

#region Globals
$script:DES_CRC        = [EncryptionType]::new("DES-CRC", 0x1)
$script:DES_MD5        = [EncryptionType]::new("DES-MD5", 0x3)
$script:RC4            = [EncryptionType]::new("RC4", 0x17)
$script:AES128         = [EncryptionType]::new("AES128-SHA96", 0x11)
$script:AES256         = [EncryptionType]::new("AES256-SHA96", 0x12)
$script:AES128_SHA256  = [EncryptionType]::new("AES128-SHA256", 0x13)
$script:AES256_SHA384  = [EncryptionType]::new("AES256-SHA384", 0x14)
$script:UnknownEType   = [EncryptionType]::new("Unknown", 0xFF)

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

# New event metadata has 21+ properties; older builds emit fewer fields.
$script:MIN_PROPERTY_COUNT = 23

# Kerberos failure / result codes (RFC 4120 §7.5.9 + Windows-specific extensions).
# Reported in 4768 "Result Code" / 4769 "Failure Code" fields.
$script:KerberosFailureCodes = @{
    0x0  = "KDC_ERR_NONE"
    0x1  = "KDC_ERR_NAME_EXP"
    0x2  = "KDC_ERR_SERVICE_EXP"
    0x3  = "KDC_ERR_BAD_PVNO"
    0x4  = "KDC_ERR_C_OLD_MAST_KVNO"
    0x5  = "KDC_ERR_S_OLD_MAST_KVNO"
    0x6  = "KDC_ERR_C_PRINCIPAL_UNKNOWN"
    0x7  = "KDC_ERR_S_PRINCIPAL_UNKNOWN"
    0x8  = "KDC_ERR_PRINCIPAL_NOT_UNIQUE"
    0x9  = "KDC_ERR_NULL_KEY"
    0xA  = "KDC_ERR_CANNOT_POSTDATE"
    0xB  = "KDC_ERR_NEVER_VALID"
    0xC  = "KDC_ERR_POLICY"
    0xD  = "KDC_ERR_BADOPTION"
    0xE  = "KDC_ERR_ETYPE_NOTSUPP"
    0xF  = "KDC_ERR_SUMTYPE_NOSUPP"
    0x10 = "KDC_ERR_PADATA_TYPE_NOSUPP"
    0x11 = "KDC_ERR_TRTYPE_NOSUPP"
    0x12 = "KDC_ERR_CLIENT_REVOKED"
    0x13 = "KDC_ERR_SERVICE_REVOKED"
    0x14 = "KDC_ERR_TGT_REVOKED"
    0x15 = "KDC_ERR_CLIENT_NOTYET"
    0x16 = "KDC_ERR_SERVICE_NOTYET"
    0x17 = "KDC_ERR_KEY_EXPIRED"
    0x18 = "KDC_ERR_PREAUTH_FAILED"
    0x19 = "KDC_ERR_PREAUTH_REQUIRED"
    0x1A = "KDC_ERR_SERVER_NOMATCH"
    0x1B = "KDC_ERR_MUST_USE_USER2USER"
    0x1F = "KRB_AP_ERR_BAD_INTEGRITY"
    0x20 = "KRB_AP_ERR_TKT_EXPIRED"
    0x21 = "KRB_AP_ERR_TKT_NYV"
    0x22 = "KRB_AP_ERR_REPEAT"
    0x23 = "KRB_AP_ERR_NOT_US"
    0x24 = "KRB_AP_ERR_BADMATCH"
    0x25 = "KRB_AP_ERR_SKEW"
    0x26 = "KRB_AP_ERR_BADADDR"
    0x27 = "KRB_AP_ERR_BADVERSION"
    0x28 = "KRB_AP_ERR_MSG_TYPE"
    0x29 = "KRB_AP_ERR_MODIFIED"
    0x2A = "KRB_AP_ERR_BADORDER"
    0x2C = "KRB_AP_ERR_BADKEYVER"
    0x2D = "KRB_AP_ERR_NOKEY"
    0x2E = "KRB_AP_ERR_MUT_FAIL"
    0x2F = "KRB_AP_ERR_BADDIRECTION"
    0x30 = "KRB_AP_ERR_METHOD"
    0x31 = "KRB_AP_ERR_BADSEQ"
    0x32 = "KRB_AP_ERR_INAPP_CKSUM"
    0x33 = "KRB_AP_PATH_NOT_ACCEPTED"
    0x34 = "KRB_ERR_RESPONSE_TOO_BIG"
    0x3C = "KRB_ERR_GENERIC"
    0x3D = "KRB_ERR_FIELD_TOOLONG"
    0x3E = "KDC_ERR_CLIENT_NOT_TRUSTED"
    0x3F = "KDC_ERR_KDC_NOT_TRUSTED"
    0x40 = "KDC_ERR_INVALID_SIG"
    0x41 = "KDC_ERR_KEY_TOO_WEAK"
    0x42 = "KDC_ERR_CERTIFICATE_MISMATCH"
    0x43 = "KRB_AP_ERR_NO_TGT"
    0x44 = "KDC_ERR_WRONG_REALM"
    0x45 = "KRB_AP_ERR_USER_TO_USER_REQUIRED"
    0x46 = "KDC_ERR_CANT_VERIFY_CERTIFICATE"
    0x47 = "KDC_ERR_INVALID_CERTIFICATE"
    0x48 = "KDC_ERR_REVOKED_CERTIFICATE"
    0x49 = "KDC_ERR_REVOCATION_STATUS_UNKNOWN"
    0x4A = "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE"
    0x4B = "KDC_ERR_CLIENT_NAME_MISMATCH"
    0x4C = "KDC_ERR_KDC_NAME_MISMATCH"
}

function Get-KerberosFailureName {
    param([uint32]$Code)
    if ($script:KerberosFailureCodes.ContainsKey([int]$Code)) {
        return $script:KerberosFailureCodes[[int]$Code]
    }
    return "Unknown"
}
#endregion

#region Functions
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

function Test-ETypeUsage {
    param(
        [string]$UsageMode,
        [EncryptionType]$TicketEtype,
        [EncryptionType]$SKEtype,
        [EncryptionType]$SearchEtype
    )

    switch ($UsageMode) {
        "Both"       { return ($TicketEtype -eq $SKEtype -and $SearchEtype -eq $TicketEtype) }
        "Ticket"     { return ($TicketEtype -eq $SearchEtype) }
        "SessionKey" { return ($SKEtype -eq $SearchEtype) }
        default      { return ($SKEtype -eq $SearchEtype -or $TicketEtype -eq $SearchEtype) }
    }
}

function ConvertTo-KerbRequest {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event
    )

    if ($Event.Properties.Count -lt $script:MIN_PROPERTY_COUNT) {
        Write-Warning "Event $($Event.RecordId) does not have the new event metadata. Skipping."
        return $null
    }

    if ($Event.Id -eq 4769) {
        # 4769 (TGS-REQ): see https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4769
        # Failure events use TicketEncryptionType 0xFFFFFFFF and a non-zero Status.
        $Target = $Event.Properties[2].Value
        $T      = Get-EncryptionType -Value $Event.Properties[5].Value
        $SK     = Get-EncryptionType -Value $Event.Properties[20].Value
        $R      = [RequestType]::TGS
        $IP     = $Event.Properties[6].Value
        $Status = [uint32]$Event.Properties[8].Value
    }
    else {
        # 4768 (AS-REQ): see https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4768
        $Target = $Event.Properties[3].Value
        $T      = Get-EncryptionType -Value $Event.Properties[7].Value
        $SK     = Get-EncryptionType -Value $Event.Properties[22].Value
        $R      = [RequestType]::AS
        $IP     = $Event.Properties[9].Value
        $Status = [uint32]$Event.Properties[6].Value
    }

    return [PSCustomObject]@{
        Request    = [KerbRequest]::new($Event.RecordId, $Event.TimeCreated, $IP, $Event.Properties[0].Value, $Target, $R, $T, $SK, $Status)
        Ticket     = $T
        SessionKey = $SK
    }
}

function Test-KerbRequestMatch {
    param(
        [EncryptionType]$Ticket,
        [EncryptionType]$SessionKey,
        [string]$EncryptionFilter,
        [string]$UsageFilter
    )

    switch ($EncryptionFilter) {
        "All" {
            return $true
        }
        "DES" {
            $d1 = Test-ETypeUsage -UsageMode $UsageFilter -TicketEtype $Ticket -SKEtype $SessionKey -SearchEtype $script:DES_CRC
            $d2 = Test-ETypeUsage -UsageMode $UsageFilter -TicketEtype $Ticket -SKEtype $SessionKey -SearchEtype $script:DES_MD5
            return ($d1 -or $d2)
        }
        "AES-SHA1" {
            $a1 = Test-ETypeUsage -UsageMode $UsageFilter -TicketEtype $Ticket -SKEtype $SessionKey -SearchEtype $script:AES128
            $a2 = Test-ETypeUsage -UsageMode $UsageFilter -TicketEtype $Ticket -SKEtype $SessionKey -SearchEtype $script:AES256
            return ($a1 -or $a2)
        }
        default {
            $etype = Get-EncryptionType -Name $EncryptionFilter
            return (Test-ETypeUsage -UsageMode $UsageFilter -TicketEtype $Ticket -SKEtype $SessionKey -SearchEtype $etype)
        }
    }
}

function Test-KerbAuditFailureEnabled {
    <#
    .SYNOPSIS
    Returns the names of Kerberos audit subcategories that do NOT have failure auditing enabled.
    .DESCRIPTION
    Failure events for 4768/4769 are only emitted when "Audit Kerberos Authentication Service"
    and "Audit Kerberos Service Ticket Operations" have Failure auditing turned on. These are
    not enabled by default. Uses auditpol.exe to inspect the effective policy.
    #>
    $subcategories = @(
        "Kerberos Authentication Service",
        "Kerberos Service Ticket Operations"
    )

    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($sub in $subcategories) {
        try {
            $output = & auditpol.exe /get /subcategory:"$sub" 2>$null
        }
        catch {
            Write-Warning "Unable to invoke auditpol.exe to verify '$sub' auditing: $_"
            return $null
        }

        if ($LASTEXITCODE -ne 0 -or -not $output) {
            Write-Warning "auditpol.exe returned no data for '$sub' (exit $LASTEXITCODE)."
            return $null
        }

        # Match the policy line, e.g.: "  Kerberos Service Ticket Operations    Success and Failure"
        $line = $output | Where-Object { $_ -match [regex]::Escape($sub) } | Select-Object -Last 1
        if (-not $line -or $line -notmatch "Failure") {
            $missing.Add($sub)
        }
    }

    # Unary comma prevents PowerShell from unrolling an empty array to $null at the call site.
    return ,$missing.ToArray()
}

function Enable-KerbAuditFailure {
    <#
    .SYNOPSIS
    Enables Failure auditing for the given Kerberos subcategories via auditpol.exe.
    Returns $true on success, $false otherwise.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Subcategories
    )

    foreach ($sub in $Subcategories) {
        try {
            & auditpol.exe /set /subcategory:"$sub" /failure:enable | Out-Null
        }
        catch {
            Write-Warning "Failed to enable failure auditing for '$sub': $_"
            return $false
        }

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "auditpol.exe exited with $LASTEXITCODE while enabling '$sub'. Are you running elevated?"
            return $false
        }
    }

    return $true
}

function Disable-KerbAuditFailure {
    <#
    .SYNOPSIS
    Disables Failure auditing for the given Kerberos subcategories via auditpol.exe.
    Returns $true on success, $false otherwise.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Subcategories
    )

    foreach ($sub in $Subcategories) {
        try {
            & auditpol.exe /set /subcategory:"$sub" /failure:disable | Out-Null
        }
        catch {
            Write-Warning "Failed to disable failure auditing for '$sub': $_"
            return $false
        }

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "auditpol.exe exited with $LASTEXITCODE while disabling '$sub'. Are you running elevated?"
            return $false
        }
    }

    return $true
}

function Watch-KerbEncryptionUsage {
    [CmdletBinding()]
    param(
        [ValidateSet("RC4", "DES", "AES-SHA1", "AES128-SHA96", "AES256-SHA96", "All")]
        [string]$Encryption = "All",
        [ValidateSet("Ticket", "SessionKey", "Either", "Both")]
        [string]$EncryptionUsage = "Either",
        [switch]$DisableFailureAuditing
    )

    $kerbAuditSubcategories = @(
        "Kerberos Authentication Service",
        "Kerberos Service Ticket Operations"
    )

    if ($DisableFailureAuditing) {
        Write-Host "Disabling Kerberos failure auditing for:" -ForegroundColor Cyan
        $kerbAuditSubcategories | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }
        if (Disable-KerbAuditFailure -Subcategories $kerbAuditSubcategories) {
            Write-Host "Failure auditing disabled." -ForegroundColor Green
        }
        else {
            Write-Warning "Failed to disable failure auditing. Are you running elevated?"
        }
        return
    }

    $missing = Test-KerbAuditFailureEnabled
    if ($null -eq $missing) {
        Write-Warning "Could not verify Kerberos failure auditing is enabled; failure events may not be captured."
    }
    elseif ($missing.Count -gt 0) {
        $list = ($missing | ForEach-Object { "  - $_" }) -join "`n"
        Write-Host "Failure auditing is not enabled for:" -ForegroundColor Yellow
        Write-Host $list -ForegroundColor Yellow
        Write-Host "Without it, 4768/4769 failure events will not be written to the Security log." -ForegroundColor Yellow

        $choice = $Host.UI.PromptForChoice(
            "Enable Kerberos failure auditing?",
            "Run auditpol.exe to enable Failure auditing for the subcategories above? (Requires elevation.)",
            @(
                [System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Enable failure auditing now."),
                [System.Management.Automation.Host.ChoiceDescription]::new("&No",  "Continue without enabling failure auditing.")
            ),
            0)

        if ($choice -eq 0) {
            if (Enable-KerbAuditFailure -Subcategories $missing) {
                Write-Host "Failure auditing enabled." -ForegroundColor Green
                Write-Host "Tip: re-run with -DisableFailureAuditing to turn it back off." -ForegroundColor DarkGray
            }
            else {
                Write-Warning "Continuing without failure auditing; failure events may be missed."
            }
        }
        else {
            Write-Warning "Continuing without failure auditing; failure events may be missed."
        }
    }

    $xpath = "*[System[(EventID=4768 or EventID=4769)]]"
    $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
        "Security",
        [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        $xpath)

    $watcher = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new($query)

    # Thread-safe queue used to hand records from the watcher callback thread
    # back to the pipeline thread for emission.
    $queue = [System.Collections.Concurrent.ConcurrentQueue[System.Diagnostics.Eventing.Reader.EventLogRecord]]::new()

    $subscription = Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -MessageData $queue -Action {
        $record = $EventArgs.EventRecord
        if ($null -ne $record) {
            $Event.MessageData.Enqueue($record)
        }
    }

    Write-Host "Watching Security log for 4768/4769 events. Press Ctrl+C to stop." -ForegroundColor Cyan
    $watcher.Enabled = $true

    # Single header for the streaming table; subsequent rows render under it.
    $rowFormat = "{0,-23}  {1,-7}  {2,-28}  {3,-16}  {4,-22}  {5,-18}  {6,-4}  {7,-12}  {8,-12}"
    $header    = $rowFormat -f "Time", "Result", "Reason", "Requestor", "Source", "Target", "Type", "Ticket", "SessionKey"
    $separator = $rowFormat -f ("-" * 23), ("-" * 7), ("-" * 28), ("-" * 16), ("-" * 22), ("-" * 18), ("-" * 4), ("-" * 12), ("-" * 12)
    Write-Host $header
    Write-Host $separator

    try {
        while ($true) {
            $record = $null
            while ($queue.TryDequeue([ref]$record)) {
                try {
                    $parsed = ConvertTo-KerbRequest -Event $record
                    if ($null -eq $parsed) { continue }

                    if (Test-KerbRequestMatch -Ticket $parsed.Ticket -SessionKey $parsed.SessionKey `
                            -EncryptionFilter $Encryption -UsageFilter $EncryptionUsage) {
                        $req     = $parsed.Request
                        $success = $req.IsSuccess()
                        $reason  = Get-KerberosFailureName -Code $req.Status
                        $line    = $rowFormat -f `
                            $req.Time.ToString("yyyy-MM-dd HH:mm:ss.fff"), `
                            $(if ($success) { "Success" } else { "Failure" }), `
                            $reason, `
                            $req.Requestor, `
                            $req.Source, `
                            $req.Target, `
                            $req.Type, `
                            $req.Ticket, `
                            $req.SessionKey
                        if ($success) {
                            Write-Host $line
                        }
                        else {
                            Write-Host $line -ForegroundColor Yellow
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to process event $($record.RecordId): $_"
                }
            }

            Start-Sleep -Milliseconds 250
        }
    }
    finally {
        $watcher.Enabled = $false
        if ($subscription) {
            Unregister-Event -SourceIdentifier $subscription.Name -ErrorAction SilentlyContinue
            Remove-Job -Id $subscription.Id -Force -ErrorAction SilentlyContinue
        }
        $watcher.Dispose()
    }
}
#endregion

if ($MyInvocation.InvocationName -ne ".") {
    Watch-KerbEncryptionUsage @PSBoundParameters
}
