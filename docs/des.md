# DES in Kerberos

## Recent Changes

- [Removal of DES in Kerberos for Windows Server and Client](https://techcommunity.microsoft.com/blog/windowsservernewsandbestpractices/removal-of-des-in-kerberos-for-windows-server-and-client/4386903)


## Detection

### Overview

Unlike some other ciphers within Kerberos, DES is not enabled by default and requires additional steps to be leveraged in an environment. Because of this, DES detection is broken down into two parts.

1. Which machines have enabled the DES ciphers as allowed encryption types?
2. Which accounts have DES keys?

### Identifying machines with the DES ciphers enabled

Starting with the first point, to leverage DES as a supported cipher, the DES needs to be configured as an [allowed encryption type](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos) which is then propagated to the [`msDS-SupportedEncryptionTypes`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919) Active Directory (AD) attribute for the account.

Meaning, if we want to quickly identify machines that are capable of leveraging DES, then we only need to query the `msDS-SupportedEncryptionTypes` attribute for that bitmask.

```powershell
PS C:\tools> Get-ADObject -Filter 'msds-SupportedEncryptionTypes -band 0x3'
DistinguishedName                             Name ObjectClass ObjectGUID
-----------------                             ---- ----------- ----------
CN=D1,OU=Domain Controllers,DC=contoso,DC=com D1   computer    86ac39a8-ffeb-49b6-b56b-2b7e8e3b64bb
CN=D2,CN=Computers,DC=contoso,DC=com          D2   computer    2cfecd60-9dcb-4297-9622-36baad2dab7d
CN=D3,CN=Computers,DC=contoso,DC=com          D3   computer    b3a7ef73-5f17-4249-982b-3e9c1bf4b697
```

Then remediation is as simple as removing DES as an allowed encryption type using the same GPO listed above.

#### Caveat

On Windows Server 2022 and older, DES is included as a part of the [DefaultDomainSupportedEncryptionTypes](https://support.microsoft.com/en-gb/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d#:~:text=the%20Kerberos%20protocol%3A-,DefaultDomainSupportedEncTypes,-Registry%20key). On Windows Server 2025 and newer, DES is **NOT** included in this value.

### Identifying accounts with DES keys

The second part of identification is related to the User Account Control (UAC) for the account. Since DES is not permitted by default in Windows environments, DES account keys are not created unless explicitly configured to do so. This configuration is handled through the [UserAccountControl](https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol) attribute in AD.

Within the Active Directory User properties window, it looks like this:

![DES user account control window](https://github.com/user-attachments/assets/187b68a6-c141-48e5-9b16-110487c03a84)

And this is what the property looks like when querying the attribute directly.

```powershell
PS C:\tools> (Get-ADUser -Identity Will -Properties UserAccountControl)
DistinguishedName  : CN=will,CN=Users,DC=contoso,DC=com
Enabled            : True
GivenName          : will
Name               : will
ObjectClass        : user
ObjectGUID         : 94855577-97b3-43b7-9abb-073abec986b9
SamAccountName     : will
SID                : S-1-5-21-4137082171-629732546-3280593868-1106
Surname            :
UserAccountControl : 2163200
UserPrincipalName  : will@contoso.com
PS C:\tools> (Get-ADUser -Identity Will -Properties UserAccountControl).UserAccountControl.ToString("x")
210200
```

Since the UserAccountControl bit `0x00200000` aka [ADS_UF_USE_DES_KEY_ONLY](https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol#:~:text=0x00200000,types%20for%20keys.) is set, this account has DES keys that can be leveraged.

Given this information, you can quickly determine which accounts are capable of using DES by querying for that bitmask.

```powershell
PS C:\tools> Get-ADObject -Filter 'UserAccountControl -band 0x00200000'

DistinguishedName                  Name ObjectClass ObjectGUID
-----------------                  ---- ----------- ----------
CN=will,CN=Users,DC=contoso,DC=com will user        94855577-97b3-43b7-9abb-073abec986b9
```

## Remediation Guidance

Now that we have identified:

1. The machines that have been configured to permit DES
2. Accounts that have DES keys

Remediation is a matter of doing the inverse.

- Ensure that DES is not configured within the [Supported Encryption Types](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
- [Disable DES keys](https://learn.microsoft.com/en-us/services-hub/unified/health/remediation-steps-ad/remove-the-highly-insecure-des-encryption-from-user-accounts) for any accounts that have it enabled
- Ensure that the [DefaultDomainSupportedEncryptionTypes](https://support.microsoft.com/en-gb/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d#:~:text=the%20Kerberos%20protocol%3A-,DefaultDomainSupportedEncTypes,-Registry%20key) does not include DES.
