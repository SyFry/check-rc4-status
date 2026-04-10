# check-rc4-status
Check your servers and accounts RC4 posture.

This borrows from MS here: https://github.com/microsoft/Kerberos-Crypto/tree/main/scripts

I wanted to make a script that checks other DC's, and reports back the status of only accounts using RC4.

# Kerberos RC4 Audit Script — Overview

**Script:** `Audit-KerberosRC4.ps1`
**Purpose:** Comprehensive audit of RC4 Kerberos encryption usage on Active Directory Domain Controllers in preparation for CVE-2026-20833 enforcement (April 2026+).

---

## What the Script Does

- **Section 1 — DC Registry Configuration:** Reads `RC4DefaultDisablementPhase` (audit/enforce/not set) and `DefaultDomainSupportedEncTypes` from each DC's registry, identifies which DCs are in enforcement mode vs audit vs unconfigured.

- **Section 2 — KRBTGT & Trust Accounts:** Checks the `msDS-SupportedEncryptionTypes` attribute on the `krbtgt` account and all AD trust objects, flags any set to RC4-only or null.

- **Section 3 — SPN Account Encryption Types:** Queries all accounts with a `servicePrincipalName` (service accounts, computer accounts, gMSAs), decodes their `msDS-SupportedEncryptionTypes`, and categorizes each as CRITICAL (RC4/DES only), HIGH (null/unset), MEDIUM (RC4+AES mixed), or OK (AES only).

- **Section 4 — Explicit RC4 Accounts:** Uses an LDAP bitwise filter to find every user/computer object in the domain that has the RC4 bit (0x4) explicitly set in `msDS-SupportedEncryptionTypes`, regardless of whether they have an SPN.

- **Section 5 — KDCSVC Audit Events 201–209:** Queries the System event log for the new CVE-2026-20833 audit/enforcement events introduced by the January 2026 update, summarizes counts by event ID with descriptions of what each means (RC4 ticket issued, blocked, etc.).

- **Section 6 — Security Log RC4 Ticket Usage:** Queries Security log events 4768 (TGT requests) and 4769 (service ticket requests), post-filters for `TicketEncryptionType = 0x17` (RC4), and shows the top accounts actively receiving RC4-encrypted tickets.

- **Section 7 — Account Keys RC4 Detection:** Replicates Microsoft's `List-AccountKeys.ps1` by reading `Properties[16]` (Available Keys) from 4768/4769 events, identifies accounts that still have RC4 registered as an available key type, separates RC4-only accounts (need password reset to generate AES keys) from RC4+AES accounts (RC4 can simply be removed).

- **Section 8 — GPO Encryption Types:** Checks the local `SupportedEncryptionTypes` registry value set by Group Policy ("Network security: Configure encryption types allowed for Kerberos"), flags if RC4 is still permitted.

- **Section 9 — Summary & Recommendations:** Rolls up all findings into actionable output — enforcement status across DCs, count of at-risk accounts by category, specific remediation steps (set `msDS-SupportedEncryptionTypes`, reset passwords, set registry phase), registry quick-reference, links to Microsoft's GitHub scripts, and the per-account RC4 exception syntax for non-Windows devices.

---

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-DaysBack` | `7` | Number of days of event log history to search |
| `-ExportPath` | `C:\Temp\RC4_Audit` | Folder for CSV output files |
| `-AllDCs` | off | Query all DCs remotely (requires WinRM and remote Event Log access) |

## Output Files

All sections export results to CSV in the export folder:

| File | Contents |
|------|----------|
| `DC_RegistryConfig.csv` | Registry settings per DC |
| `SPN_Accounts_EncryptionTypes.csv` | All SPN-bearing accounts with risk ratings |
| `Explicit_RC4_Accounts.csv` | Accounts with RC4 bit explicitly set |
| `KDCSVC_Events.csv` | KDCSVC 201–209 event details |
| `RC4_Ticket_Events.csv` | 4768/4769 events with RC4 ticket encryption |
| `RC4_AccountKeys.csv` | Accounts with RC4 in available Kerberos keys |

## Prerequisites

- Run on a Domain Controller as Domain Admin or equivalent
- `ActiveDirectory` PowerShell module
- January 2025+ cumulative update for Available Keys event metadata (Section 7)
- January 2026+ cumulative update for KDCSVC 201–209 events (Section 5)

## References

- [KB5073381 / CVE-2026-20833 — Microsoft Support](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
- [Detect and Remediate RC4 Usage in Kerberos — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Kerberos-Crypto Scripts — GitHub](https://github.com/microsoft/Kerberos-Crypto/tree/main/scripts)
