#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Audits Kerberos RC4 encryption usage on AD DCs for CVE-2026-20833.
.DESCRIPTION
    RMM-compatible version. Checks registry config, SPN accounts, KDCSVC
    events 201-209, Security log 4768/4769 for RC4 tickets, and GPO settings.
.PARAMETER DaysBack
    Days of event log history to search. Default: 7.
.PARAMETER ExportPath
    Folder for CSV output. Default: C:\Temp\RC4_Audit.
.PARAMETER AllDCs
    Query all DCs remotely (requires remote Event Log + WinRM).
#>

[CmdletBinding()]
param(
    [int]$DaysBack = 7,
    [string]$ExportPath = 'C:\Temp\RC4_Audit',
    [switch]$AllDCs
)

$ErrorActionPreference = 'Continue'

#region --- Constants ---
$RC4_BIT     = 0x4
$DES_BITS    = 0x3
$AES128_BIT  = 0x8
$AES256_BIT  = 0x10
$AES_BITS    = 0x18
$FUTURE_BIT  = [int]0x80000000
#endregion

#region --- Helper Functions ---

function Decode-EncryptionTypes {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -eq 0) { return 'Not Set (KDC Default)' }
    $v = [int]$Value
    $flags = @()
    if ($v -band 0x1)         { $flags += 'DES_CBC_CRC' }
    if ($v -band 0x2)         { $flags += 'DES_CBC_MD5' }
    if ($v -band $RC4_BIT)    { $flags += 'RC4_HMAC' }
    if ($v -band $AES128_BIT) { $flags += 'AES128_SHA1' }
    if ($v -band $AES256_BIT) { $flags += 'AES256_SHA1' }
    if ($v -band $FUTURE_BIT) { $flags += 'FutureEtypes' }
    $joined = $flags -join ', '
    $hex = '0x{0:X}' -f $v
    return ('{0} ({1})' -f $joined, $hex)
}

function Get-EncryptionTypeRisk {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -eq 0) {
        return 'HIGH - Null/default, will use KDC assumed etypes (RC4 pre-enforcement)'
    }
    $v = [int]$Value
    $hasAES = ($v -band $AES_BITS) -ne 0
    $hasRC4 = ($v -band $RC4_BIT) -ne 0
    $hasDES = ($v -band $DES_BITS) -ne 0
    if (-not $hasAES -and $hasRC4) { return 'CRITICAL - RC4 only, will break at enforcement' }
    if ($hasRC4 -and $hasAES)      { return 'MEDIUM - RC4 + AES set, RC4 can be removed' }
    if ($hasDES -and -not $hasAES) { return 'CRITICAL - DES only, will break at enforcement' }
    if ($hasAES -and -not $hasRC4) { return 'OK - AES only' }
    return ('UNKNOWN (0x{0:X})' -f $v)
}

function Write-Section {
    param([string]$Title)
    $sep = '=' * 80
    Write-Host ''
    Write-Host $sep -ForegroundColor Cyan
    Write-Host ('  {0}' -f $Title) -ForegroundColor Cyan
    Write-Host $sep -ForegroundColor Cyan
}

#endregion

#region --- Setup ---

if (-not (Test-Path $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
}

$domain   = Get-ADDomain
$domainDN = $domain.DistinguishedName

if ($AllDCs) {
    $dcList = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
} else {
    $dcList = @($env:COMPUTERNAME)
}

$dnsRoot  = $domain.DNSRoot
$dcCount  = $dcList.Count
$runTime  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

Write-Host ''
Write-Host '================================================================' -ForegroundColor Yellow
Write-Host '  Kerberos RC4 Audit for CVE-2026-20833 / KB5073381' -ForegroundColor Yellow
Write-Host ('  Domain : {0}' -f $dnsRoot) -ForegroundColor Yellow
Write-Host ('  DCs    : {0}' -f $dcCount) -ForegroundColor Yellow
Write-Host ('  Window : Last {0} days' -f $DaysBack) -ForegroundColor Yellow
Write-Host ('  Run at : {0}' -f $runTime) -ForegroundColor Yellow
Write-Host '================================================================' -ForegroundColor Yellow

#endregion

#region --- 1. DC Registry Keys ---

Write-Section '1. Domain Controller Registry Configuration'

$kerbParamsPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
$regResults = @()

foreach ($dc in $dcList) {
    Write-Host ('  Checking {0} ...' -f $dc) -ForegroundColor Gray
    try {
        if ($dc -eq $env:COMPUTERNAME) {
            $rc4Phase = (Get-ItemProperty -Path $kerbParamsPath -Name 'RC4DefaultDisablementPhase' -ErrorAction SilentlyContinue).RC4DefaultDisablementPhase
            $ddset    = (Get-ItemProperty -Path $kerbParamsPath -Name 'DefaultDomainSupportedEncTypes' -ErrorAction SilentlyContinue).DefaultDomainSupportedEncTypes
        } else {
            $rc4Phase = Invoke-Command -ComputerName $dc -ScriptBlock {
                (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'RC4DefaultDisablementPhase' -ErrorAction SilentlyContinue).RC4DefaultDisablementPhase
            } -ErrorAction Stop
            $ddset = Invoke-Command -ComputerName $dc -ScriptBlock {
                (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'DefaultDomainSupportedEncTypes' -ErrorAction SilentlyContinue).DefaultDomainSupportedEncTypes
            } -ErrorAction Stop
        }

        $phaseText = switch ($rc4Phase) {
            $null   { 'Not Set (default behavior per installed update)' }
            0       { '0 - Disabled (no auditing, no RC4 changes)' }
            1       { '1 - Audit Mode (logging only, RC4 still allowed)' }
            2       { '2 - Enforcement Mode (RC4 blocked for default accounts)' }
            default { '{0} - Unknown value' -f $rc4Phase }
        }

        $ddsetText = if ($null -eq $ddset) { 'Not Set (OS default applies)' } else { Decode-EncryptionTypes $ddset }

        $regResults += [PSCustomObject]@{
            DomainController              = $dc
            RC4DefaultDisablementPhase    = $phaseText
            DefaultDomainSupportedEncTypes = $ddsetText
        }

        $color = if ($rc4Phase -eq 2) { 'Green' } elseif ($rc4Phase -eq 1) { 'Yellow' } else { 'Red' }
        Write-Host ('    RC4DefaultDisablementPhase     : {0}' -f $phaseText) -ForegroundColor $color
        Write-Host ('    DefaultDomainSupportedEncTypes : {0}' -f $ddsetText) -ForegroundColor Gray
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-Host ('    ERROR connecting to {0}: {1}' -f $dc, $errMsg) -ForegroundColor Red
        $regResults += [PSCustomObject]@{
            DomainController              = $dc
            RC4DefaultDisablementPhase    = 'ERROR: {0}' -f $errMsg
            DefaultDomainSupportedEncTypes = 'ERROR'
        }
    }
}
$regResults | Export-Csv -Path (Join-Path $ExportPath 'DC_RegistryConfig.csv') -NoTypeInformation

#endregion

#region --- 2. KRBTGT and Trust Accounts ---

Write-Section '2. KRBTGT and Trust Account Encryption Types'

$krbtgt = Get-ADUser 'krbtgt' -Properties msDS-SupportedEncryptionTypes
$krbtgtEtype = $krbtgt.'msDS-SupportedEncryptionTypes'
Write-Host ('  krbtgt : {0}' -f (Decode-EncryptionTypes $krbtgtEtype)) -ForegroundColor Gray

$trusts = Get-ADObject -Filter 'objectClass -eq "trustedDomain"' -Properties msDS-SupportedEncryptionTypes, flatName
foreach ($t in $trusts) {
    $tEtype = $t.'msDS-SupportedEncryptionTypes'
    $risk = Get-EncryptionTypeRisk $tEtype
    $color = if ($risk -match '^OK') { 'Green' } elseif ($risk -match 'CRITICAL') { 'Red' } else { 'Yellow' }
    Write-Host ('  Trust: {0} : {1} [{2}]' -f $t.flatName, (Decode-EncryptionTypes $tEtype), $risk) -ForegroundColor $color
}

#endregion

#region --- 3. SPN Accounts - Encryption Type Analysis ---

Write-Section '3. Accounts with SPNs - Encryption Type Analysis'

Write-Host '  Querying accounts with servicePrincipalName set ...' -ForegroundColor Gray

$spnAccounts = Get-ADObject -LDAPFilter '(servicePrincipalName=*)' `
    -Properties sAMAccountName, objectClass, servicePrincipalName, msDS-SupportedEncryptionTypes, pwdLastSet, whenChanged `
    -SearchBase $domainDN |
    Where-Object { $_.objectClass -in @('user','computer','msDS-GroupManagedServiceAccount','msDS-ManagedServiceAccount') }

$spnResults = @()
$critCount = 0; $medCount = 0; $nullCount = 0; $okCount = 0

foreach ($acct in $spnAccounts) {
    $etype   = $acct.'msDS-SupportedEncryptionTypes'
    $risk    = Get-EncryptionTypeRisk $etype
    $decoded = Decode-EncryptionTypes $etype

    if ($risk -match 'CRITICAL')   { $critCount++ }
    elseif ($risk -match 'HIGH')   { $nullCount++ }
    elseif ($risk -match 'MEDIUM') { $medCount++ }
    else                           { $okCount++ }

    $spnList = ($acct.servicePrincipalName | Select-Object -First 3) -join '; '

    $spnResults += [PSCustomObject]@{
        Account         = $acct.sAMAccountName
        ObjectClass     = $acct.objectClass
        EncryptionTypes = $decoded
        RawValue        = $etype
        Risk            = $risk
        PasswordLastSet = $acct.whenChanged
        SPN             = $spnList
    }
}

$totalSPN = @($spnAccounts).Count
Write-Host ''
Write-Host ('  Summary of {0} SPN-bearing accounts:' -f $totalSPN) -ForegroundColor White
Write-Host ('    CRITICAL (RC4/DES only)  : {0}' -f $critCount) -ForegroundColor Red
Write-Host ('    HIGH (Null/unset)        : {0}' -f $nullCount) -ForegroundColor Red
Write-Host ('    MEDIUM (RC4 + AES mixed) : {0}' -f $medCount) -ForegroundColor Yellow
Write-Host ('    OK (AES only)            : {0}' -f $okCount) -ForegroundColor Green

$problemAccounts = $spnResults | Where-Object { $_.Risk -match 'CRITICAL|HIGH' }
if ($problemAccounts) {
    Write-Host ''
    Write-Host '  Accounts requiring action BEFORE enforcement:' -ForegroundColor Red
    $tableOutput = $problemAccounts | Sort-Object Risk | Format-Table Account, ObjectClass, EncryptionTypes, Risk -AutoSize | Out-String
    Write-Host $tableOutput
}

$spnResults | Export-Csv -Path (Join-Path $ExportPath 'SPN_Accounts_EncryptionTypes.csv') -NoTypeInformation

#endregion

#region --- 4. All accounts with explicit RC4 ---

Write-Section '4. All Accounts with Explicit RC4 in msDS-SupportedEncryptionTypes'

# LDAP bitwise AND filter for RC4 bit (0x4) - single-quoted to avoid pipe/paren parsing
$rc4Filter = '(&(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=4)(|(objectClass=user)(objectClass=computer)))'
$rc4Accounts = Get-ADObject -LDAPFilter $rc4Filter `
    -Properties sAMAccountName, objectClass, msDS-SupportedEncryptionTypes, servicePrincipalName, pwdLastSet, whenChanged

$rc4AccountResults = foreach ($acct in $rc4Accounts) {
    $hasSPN = ($null -ne $acct.servicePrincipalName -and $acct.servicePrincipalName.Count -gt 0)
    [PSCustomObject]@{
        Account         = $acct.sAMAccountName
        ObjectClass     = $acct.objectClass
        EncryptionTypes = Decode-EncryptionTypes ($acct.'msDS-SupportedEncryptionTypes')
        RawValue        = $acct.'msDS-SupportedEncryptionTypes'
        HasSPN          = $hasSPN
        Risk            = Get-EncryptionTypeRisk ($acct.'msDS-SupportedEncryptionTypes')
        PasswordLastSet = $acct.whenChanged
    }
}

$rc4ExplicitCount = @($rc4AccountResults).Count
$rc4Color = if ($rc4ExplicitCount -gt 0) { 'Yellow' } else { 'Green' }
Write-Host ('  Found {0} accounts with explicit RC4 bit set.' -f $rc4ExplicitCount) -ForegroundColor $rc4Color

if ($rc4AccountResults) {
    $rc4AccountResults | Export-Csv -Path (Join-Path $ExportPath 'Explicit_RC4_Accounts.csv') -NoTypeInformation
    Write-Host ('  Exported to {0}\Explicit_RC4_Accounts.csv' -f $ExportPath)
}

#endregion

#region --- 5. KDCSVC Events 201-209 ---

Write-Section '5. KDCSVC Audit Events 201-209 (CVE-2026-20833)'

Write-Host '  These events require Jan 2026+ updates and RC4DefaultDisablementPhase >= 1.' -ForegroundColor Gray

$kdcEventResults = @()

foreach ($dc in $dcList) {
    Write-Host ('  Querying System log on {0} ...' -f $dc) -ForegroundColor Gray
    try {
        # Use FilterHashtable without ProviderName (not supported on all OS versions)
        # Post-filter for KDCSVC provider
        $filterHash = @{
            LogName      = 'System'
            Id           = @(201,202,203,204,205,206,207,208,209)
            StartTime    = (Get-Date).AddDays(-$DaysBack)
        }
        $getParams = @{
            FilterHashtable = $filterHash
            ErrorAction     = 'SilentlyContinue'
        }
        if ($dc -ne $env:COMPUTERNAME) { $getParams['ComputerName'] = $dc }

        $allEvents = Get-WinEvent @getParams
        # Post-filter for KDCSVC provider
        $events = $allEvents | Where-Object { $_.ProviderName -eq 'KDCSVC' }
        if ($events) {
            Write-Host ('    Found {0} KDCSVC events on {1}' -f $events.Count, $dc) -ForegroundColor Yellow
            foreach ($evt in $events) {
                $msgSnippet = $evt.Message
                if ($msgSnippet.Length -gt 500) { $msgSnippet = $msgSnippet.Substring(0, 500) }
                $kdcEventResults += [PSCustomObject]@{
                    DC          = $dc
                    TimeCreated = $evt.TimeCreated
                    EventID     = $evt.Id
                    Level       = $evt.LevelDisplayName
                    Message     = $msgSnippet
                }
            }
        } else {
            Write-Host ('    No KDCSVC 201-209 events found on {0} (updates not installed or phase=0)' -f $dc) -ForegroundColor Green
        }
    }
    catch {
        Write-Host ('    ERROR reading events from {0}: {1}' -f $dc, $_.Exception.Message) -ForegroundColor Red
    }
}

if ($kdcEventResults) {
    $grouped = $kdcEventResults | Group-Object EventID | Sort-Object Name
    Write-Host ''
    Write-Host '  KDCSVC Event Summary:' -ForegroundColor White

    $eventDescriptions = @{
        '201' = 'Audit: RC4 service ticket issued (default account)'
        '202' = 'Audit: RC4 session key issued'
        '203' = 'Enforce: RC4 service ticket BLOCKED (default account)'
        '204' = 'Enforce: RC4 session key BLOCKED'
        '205' = 'Warning: DefaultDomainSupportedEncTypes includes RC4'
        '206' = 'Audit: RC4 service ticket (explicit account config)'
        '207' = 'Enforce: RC4 service ticket (explicit account config)'
        '208' = 'Audit: RC4 session key (explicit account config)'
        '209' = 'Enforce: RC4 session key (explicit account config)'
    }

    foreach ($g in $grouped) {
        $desc = $eventDescriptions[$g.Name]
        if (-not $desc) { $desc = 'Unknown' }
        $color = if ($g.Name -in @('203','204','207','209')) { 'Red' } else { 'Yellow' }
        Write-Host ('    Event {0}: {1} occurrences - {2}' -f $g.Name, $g.Count, $desc) -ForegroundColor $color
    }
    $kdcEventResults | Export-Csv -Path (Join-Path $ExportPath 'KDCSVC_Events.csv') -NoTypeInformation
}

#endregion

#region --- 6. Security Log 4768/4769 with RC4 ---

Write-Section '6. Security Log - Kerberos RC4 Ticket Usage (4768/4769)'

$rc4TicketResults = @()

foreach ($dc in $dcList) {
    Write-Host ('  Querying Security log on {0} for RC4 tickets ...' -f $dc) -ForegroundColor Gray
    try {
        foreach ($eid in @(4768, 4769)) {
            # Use FilterHashtable + post-filter for RC4 to avoid XML entity issues
            $filterHash = @{
                LogName   = 'Security'
                Id        = $eid
                StartTime = (Get-Date).AddDays(-$DaysBack)
            }
            $getParams = @{
                FilterHashtable = $filterHash
                MaxEvents       = 500
                ErrorAction     = 'SilentlyContinue'
            }
            if ($dc -ne $env:COMPUTERNAME) { $getParams['ComputerName'] = $dc }

            $events = Get-WinEvent @getParams

            # Post-filter for RC4 encryption type (0x17)
            $rc4Events = @()
            if ($events) {
                foreach ($evt in $events) {
                    $evtXml = [xml]$evt.ToXml()
                    $dataNodes = $evtXml.Event.EventData.Data
                    $ticketEtype = ($dataNodes | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
                    if ($ticketEtype -eq '0x17') {
                        $rc4Events += $evt
                    }
                }
            }

            if ($rc4Events.Count -gt 0) {
                Write-Host ('    {0} - Event {1} : {2} RC4 tickets found' -f $dc, $eid, $rc4Events.Count) -ForegroundColor Yellow
                foreach ($evt in ($rc4Events | Select-Object -First 100)) {
                    $evtXml = [xml]$evt.ToXml()
                    $data = @{}
                    foreach ($d in $evtXml.Event.EventData.Data) {
                        $data[$d.Name] = $d.'#text'
                    }
                    $acctName = if ($eid -eq 4768) { $data['TargetUserName'] } else { $data['ServiceName'] }
                    $sessEtype = if ($data['SessionEncryptionType']) { $data['SessionEncryptionType'] } else { 'N/A' }
                    $rc4TicketResults += [PSCustomObject]@{
                        DC           = $dc
                        TimeCreated  = $evt.TimeCreated
                        EventID      = $eid
                        Account      = $acctName
                        ClientAddr   = $data['IpAddress']
                        TicketEtype  = $data['TicketEncryptionType']
                        SessionEtype = $sessEtype
                    }
                }
            } else {
                Write-Host ('    {0} - Event {1} : No RC4 tickets found' -f $dc, $eid) -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host ('    ERROR reading Security log on {0}: {1}' -f $dc, $_.Exception.Message) -ForegroundColor Red
    }
}

if ($rc4TicketResults) {
    $byAccount = $rc4TicketResults | Group-Object Account | Sort-Object Count -Descending
    Write-Host ''
    Write-Host '  Top accounts receiving RC4 tickets:' -ForegroundColor White
    $byAccount | Select-Object -First 20 | ForEach-Object {
        $countPad = $_.Count.ToString().PadLeft(6)
        Write-Host ('    {0}x  {1}' -f $countPad, $_.Name) -ForegroundColor Yellow
    }
    $rc4TicketResults | Export-Csv -Path (Join-Path $ExportPath 'RC4_Ticket_Events.csv') -NoTypeInformation
}

#endregion

#region --- 7. Account Keys Analysis (List-AccountKeys equivalent) ---

Write-Section '7. Account Keys - RC4 Key Detection (4768/4769)'

Write-Host '  Scanning Security log for accounts with RC4 in Available Keys ...' -ForegroundColor Gray
Write-Host ('  Looking back {0} days. Requires Jan 2025+ updates for key metadata.' -f $DaysBack) -ForegroundColor Gray

# Minimum property count for new event schema with Available Keys field
$MIN_PROPERTY_COUNT = 21

$rc4KeyAccounts = @{}
$schemaValid = $true

foreach ($dc in $dcList) {
    Write-Host ('  Querying {0} ...' -f $dc) -ForegroundColor Gray
    try {
        foreach ($eid in @(4768, 4769)) {
            $filterHash = @{
                LogName   = 'Security'
                Id        = $eid
                StartTime = (Get-Date).AddDays(-$DaysBack)
            }
            $getParams = @{
                FilterHashtable = $filterHash
                ErrorAction     = 'SilentlyContinue'
            }
            if ($dc -ne $env:COMPUTERNAME) { $getParams['ComputerName'] = $dc }

            $events = Get-WinEvent @getParams

            if (-not $events) { continue }

            # Validate event schema has the new Available Keys field
            if ($events[0].Properties.Count -lt $MIN_PROPERTY_COUNT) {
                Write-Host ('    WARNING: Event schema on {0} has only {1} properties (need {2}+).' -f $dc, $events[0].Properties.Count, $MIN_PROPERTY_COUNT) -ForegroundColor Yellow
                Write-Host '    Install the latest cumulative updates to get Available Keys metadata.' -ForegroundColor Yellow
                $schemaValid = $false
                continue
            }

            foreach ($evt in $events) {
                # Properties[16] = Available Keys (comma-separated string like "RC4, AES128-SHA96, AES256-SHA96")
                [string]$keysRaw = $evt.Properties[16].Value
                if ([string]::IsNullOrEmpty($keysRaw)) { continue }

                # Only care about accounts that have RC4 in their key list
                if ($keysRaw -notmatch 'RC4') { continue }

                # Extract account name
                if ($eid -eq 4769) {
                    # 4769 (TGS): Properties[2] = Service Name
                    $acctName = [string]$evt.Properties[2].Value
                } else {
                    # 4768 (AS/TGT): Properties[0] = Target User Name
                    $acctName = [string]$evt.Properties[0].Value
                }

                if ([string]::IsNullOrEmpty($acctName)) { continue }

                # Determine account type
                $acctType = if ($acctName.EndsWith('$')) { 'Machine' } else { 'User' }

                # Normalize keys: expand "AES-SHA1" shorthand used on Server 2022
                $keysList = $keysRaw.Split(',') | ForEach-Object {
                    $k = $_.Trim()
                    if ($k -eq 'AES-SHA1') {
                        'AES128-SHA96'
                        'AES256-SHA96'
                    } else {
                        $k
                    }
                }
                $keysNormalized = ($keysList | Select-Object -Unique) -join '; '

                # Deduplicate: keep most recent occurrence per account
                $key = '{0}|{1}' -f $acctName, $dc
                if (-not $rc4KeyAccounts.ContainsKey($key) -or $evt.TimeCreated -gt $rc4KeyAccounts[$key].TimeCreated) {
                    $rc4KeyAccounts[$key] = [PSCustomObject]@{
                        Account     = $acctName
                        Type        = $acctType
                        Keys        = $keysNormalized
                        DC          = $dc
                        TimeCreated = $evt.TimeCreated
                        RC4Only     = ($keysList | Where-Object { $_ -match 'AES|SHA' }).Count -eq 0
                    }
                }
            }
        }
    }
    catch {
        Write-Host ('    ERROR: {0}' -f $_.Exception.Message) -ForegroundColor Red
    }
}

if (-not $schemaValid -and $rc4KeyAccounts.Count -eq 0) {
    Write-Host '' 
    Write-Host '  SKIPPED: Event schema does not include Available Keys field.' -ForegroundColor Yellow
    Write-Host '  This requires Windows Server 2019+ with recent cumulative updates,' -ForegroundColor Yellow
    Write-Host '  or Server 2016 with the January 2025 cumulative update.' -ForegroundColor Yellow
} elseif ($rc4KeyAccounts.Count -eq 0) {
    Write-Host ''
    Write-Host '  CLEAN: No accounts found with RC4 in their available Kerberos keys.' -ForegroundColor Green
} else {
    $rc4KeyList = $rc4KeyAccounts.Values | Sort-Object RC4Only, Account -Descending

    $rc4OnlyCount = @($rc4KeyList | Where-Object { $_.RC4Only }).Count
    $rc4MixedCount = $rc4KeyList.Count - $rc4OnlyCount

    Write-Host ''
    Write-Host ('  Found {0} accounts with RC4 in available keys:' -f $rc4KeyList.Count) -ForegroundColor Yellow
    if ($rc4OnlyCount -gt 0) {
        Write-Host ('    RC4 ONLY (no AES keys - password reset needed) : {0}' -f $rc4OnlyCount) -ForegroundColor Red
    }
    if ($rc4MixedCount -gt 0) {
        Write-Host ('    RC4 + AES (RC4 can be removed)                 : {0}' -f $rc4MixedCount) -ForegroundColor Yellow
    }

    Write-Host ''
    # Show RC4-only accounts first (most critical)
    $rc4OnlyAccounts = $rc4KeyList | Where-Object { $_.RC4Only }
    if ($rc4OnlyAccounts) {
        Write-Host '  CRITICAL - Accounts with ONLY RC4 keys (need password reset to generate AES):' -ForegroundColor Red
        $rc4OnlyAccounts | Format-Table Account, Type, Keys, DC -AutoSize | Out-String | Write-Host
    }

    # Then show mixed accounts
    $rc4MixedAccounts = $rc4KeyList | Where-Object { -not $_.RC4Only }
    if ($rc4MixedAccounts) {
        Write-Host '  MEDIUM - Accounts with RC4 + AES keys:' -ForegroundColor Yellow
        $rc4MixedAccounts | Format-Table Account, Type, Keys, DC -AutoSize | Out-String | Write-Host
    }

    $rc4KeyList | Export-Csv -Path (Join-Path $ExportPath 'RC4_AccountKeys.csv') -NoTypeInformation
    Write-Host ('  Exported to {0}\RC4_AccountKeys.csv' -f $ExportPath)
}

#endregion

#region --- 8. GPO Kerberos Encryption Types ---

Write-Section '8. Local Policy - Allowed Kerberos Encryption Types'

$allowedEtypes = (Get-ItemProperty -Path $kerbParamsPath -Name 'SupportedEncryptionTypes' -ErrorAction SilentlyContinue).SupportedEncryptionTypes

if ($null -eq $allowedEtypes) {
    Write-Host '  SupportedEncryptionTypes (GPO) : Not configured (OS default)' -ForegroundColor Gray
} else {
    $decoded = Decode-EncryptionTypes $allowedEtypes
    $hasRC4 = ($allowedEtypes -band $RC4_BIT) -ne 0
    $color = if ($hasRC4) { 'Yellow' } else { 'Green' }
    Write-Host ('  SupportedEncryptionTypes (GPO) : {0}' -f $decoded) -ForegroundColor $color
    if ($hasRC4) {
        Write-Host '  WARNING: GPO still permits RC4 encryption for Kerberos clients on this DC.' -ForegroundColor Yellow
    }
}

#endregion

#region --- 9. Summary ---

Write-Section '9. Summary and Recommendations'

$enforcement = $regResults | Where-Object { $_.RC4DefaultDisablementPhase -match '2 - Enforcement' }
$auditMode   = $regResults | Where-Object { $_.RC4DefaultDisablementPhase -match '1 - Audit' }
$notSet      = $regResults | Where-Object { $_.RC4DefaultDisablementPhase -match 'Not Set' }

$enfCount  = @($enforcement).Count
$audCount  = @($auditMode).Count
$nsCount   = @($notSet).Count

Write-Host ''
Write-Host '  ENFORCEMENT STATUS:' -ForegroundColor White
$enfColor = if ($enfCount -eq $dcCount) { 'Green' } else { 'Red' }
$audColor = if ($audCount -gt 0) { 'Yellow' } else { 'Gray' }
$nsColor  = if ($nsCount -gt 0) { 'Red' } else { 'Gray' }
Write-Host ('    DCs in Enforcement Mode : {0} / {1}' -f $enfCount, $dcCount) -ForegroundColor $enfColor
Write-Host ('    DCs in Audit Mode       : {0} / {1}' -f $audCount, $dcCount) -ForegroundColor $audColor
Write-Host ('    DCs Not Configured      : {0} / {1}' -f $nsCount, $dcCount) -ForegroundColor $nsColor
Write-Host ''

Write-Host '  ACTIONS REQUIRED:' -ForegroundColor White
if ($critCount -gt 0) {
    Write-Host ('  [!] {0} SPN accounts have RC4/DES ONLY - these WILL BREAK at enforcement.' -f $critCount) -ForegroundColor Red
    Write-Host '      Fix: Set msDS-SupportedEncryptionTypes to 0x18 (AES only) or 0x1C (AES+RC4)' -ForegroundColor Red
    Write-Host '      Then reset the account password to generate AES keys.' -ForegroundColor Red
}
if ($nullCount -gt 0) {
    Write-Host ('  [!] {0} SPN accounts have NULL msDS-SupportedEncryptionTypes.' -f $nullCount) -ForegroundColor Yellow
    Write-Host '      These rely on KDC default. After enforcement, KDC assumes AES only.' -ForegroundColor Yellow
    Write-Host '      Non-Windows devices in this group may break. Test or set explicit AES.' -ForegroundColor Yellow
}
if ($medCount -gt 0) {
    Write-Host ('  [i] {0} SPN accounts have RC4+AES. These will continue to work but' -f $medCount) -ForegroundColor Yellow
    Write-Host '      consider removing RC4 bit (set to 0x18) for full hardening.' -ForegroundColor Yellow
}
if ($nsCount -gt 0) {
    Write-Host ('  [!] {0} DCs do not have RC4DefaultDisablementPhase set.' -f $nsCount) -ForegroundColor Red
    Write-Host '      April 2026 updates will auto-enable enforcement.' -ForegroundColor Red
    Write-Host '      Set to 1 (audit) first, monitor KDCSVC 201-209, then move to 2 (enforce).' -ForegroundColor Red
}
$kdcEvtCount = @($kdcEventResults).Count
if ($kdcEvtCount -eq 0 -and $nsCount -gt 0) {
    Write-Host '  [?] No KDCSVC events found. Ensure Jan 2026+ updates are installed and' -ForegroundColor Yellow
    Write-Host '      RC4DefaultDisablementPhase is set to at least 1 to enable auditing.' -ForegroundColor Yellow
}
$rc4KeyTotal = $rc4KeyAccounts.Count
$rc4OnlyTotal = @($rc4KeyAccounts.Values | Where-Object { $_.RC4Only }).Count
if ($rc4KeyTotal -gt 0) {
    Write-Host ('  [!] {0} accounts have RC4 in their available Kerberos keys.' -f $rc4KeyTotal) -ForegroundColor Yellow
    if ($rc4OnlyTotal -gt 0) {
        Write-Host ('  [!] {0} of those have ONLY RC4 keys (no AES). Reset their passwords to' -f $rc4OnlyTotal) -ForegroundColor Red
        Write-Host '      generate AES keys, then remove RC4 from msDS-SupportedEncryptionTypes.' -ForegroundColor Red
    }
} elseif ($schemaValid) {
    Write-Host '  [OK] No accounts found with RC4 in their available Kerberos keys.' -ForegroundColor Green
}
Write-Host ''

Write-Host '  REGISTRY QUICK-REFERENCE:' -ForegroundColor White
Write-Host '    Path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -ForegroundColor Gray
Write-Host '    RC4DefaultDisablementPhase (REG_DWORD):' -ForegroundColor Gray
Write-Host '      0 = No changes     1 = Audit mode     2 = Enforcement mode' -ForegroundColor Gray
Write-Host '    * Reboot required after changes *' -ForegroundColor Gray
Write-Host ''

Write-Host '  MICROSOFT SCRIPTS (recommended for deeper analysis):' -ForegroundColor White
Write-Host '    https://github.com/microsoft/Kerberos-Crypto/tree/main/scripts' -ForegroundColor Gray
Write-Host '      - Get-KerbEncryptionUsage.ps1 -Encryption RC4 -EncryptionUsage Ticket' -ForegroundColor Gray
Write-Host '      - List-AccountKeys.ps1 -ContainsKeyType RC4' -ForegroundColor Gray
Write-Host ''

Write-Host '  PER-ACCOUNT RC4 EXCEPTION (last resort for non-Windows devices):' -ForegroundColor White
Write-Host '    Set-ADObject <DN> -Replace @{msDS-SupportedEncryptionTypes=0x24}' -ForegroundColor Gray
Write-Host '    (0x24 = RC4 + AES session keys -- still vulnerable, use temporarily)' -ForegroundColor Gray
Write-Host ''

Write-Host ('  All CSVs exported to: {0}' -f $ExportPath) -ForegroundColor Green
Write-Host ''

#endregion
