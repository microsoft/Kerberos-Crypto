# RC4 in Kerberos

RC4 (ARCFOUR-HMAC-MD5, etype 0x17) is a legacy cipher suite still present in many Active Directory environments. While not as critically broken as DES, RC4 lacks the security properties of AES and is increasingly being deprecated.

This page serves as a hub for RC4-related documentation, guidance, and tooling.

## Recent changes

- [How to manage Kerberos KDC usage of RC4 for service account ticket issuance](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
- [Ask Directory Services Team: What is going on with RC4 in Kerberos](https://techcommunity.microsoft.com/blog/askds/what-is-going-on-with-rc4-in-kerberos/4489365)
- [Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Beyond RC4 for Windows authentication](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/)

## Detection

### Identifying RC4 ticket or session key usage

Use the [`Get-KerbEncryptionUsage.ps1`](../scripts/Get-KerbEncryptionUsage.ps1) script to check for RC4 usage:

```powershell
.\scripts\Get-KerbEncryptionUsage.ps1 -Encryption RC4
```

### Identifying accounts restricted to RC4

Accounts that only support RC4 will have `msDS-SupportedEncryptionTypes` set to `0x4` (RC4 only) or otherwise lack the AES bits (`0x8` for AES128, `0x10` for AES256):

```powershell
# Accounts that explicitly list RC4 but NOT AES
Get-ADObject -Filter 'msds-SupportedEncryptionTypes -band 0x4 -and -not msds-SupportedEncryptionTypes -band 0x18'
```

## Remediation Guidance

- [Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

## Additional Information

- [MS-KILE 2.2.7 Supported Encryption Types Bit Flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919)
- [Network security: Configure encryption types allowed for Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
- [Microsoft's guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [KB5021131: How to manage the Kerberos protocol changes related to CVE-2022-37966](https://support.microsoft.com/en-gb/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)