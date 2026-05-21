BeforeAll {

    $script:AES_4769_EVENT = [PSCustomObject]@{
        RecordId    = 1
        MachineName = "KDC1"
        Id          = 4769
        TimeCreated = $(Get-Date)
        Properties  = @(
            @{Value = 'KDC$@CONTOSO.COM' }
            @{Value = 'CONTOSO.COM' }
            @{Value = 'KDC2$' }
            @{Value = 'S-1-5-21-2525879430-3093583400-2026621138-1105' }
            @{Value = '1082195968' }
            @{Value = '18' }
            @{Value = '::1' }
            @{Value = '0' }
            @{Value = '0' }
            @{Value = 'ad136b76-daa7-8e25-31d7-3f2e21df6a36' }
            @{Value = '-' }
            @{Value = 'vs+nolPjeVqyWyaMVz3dW/K/EmUqQy15MW0qP+rijVY=' }
            @{Value = 'fJI8TXEUFCezq+zYhyKW4vggnQS+eaiaHXPAXIeqoDY=' }
            @{Value = 'N/A' }
            @{Value = 'N/A' }
            @{Value = '0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)' }
            @{Value = 'AES-SHA1, RC4' }
            @{Value = '0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)' }
            @{Value = 'AES-SHA1, RC4' }
            @{Value = '...' }
            @{Value = '18' }
        )
    }

    $script:4769_NEW_FORMAT = [PSCustomObject]@{
        RecordId    = 1
        MachineName = "KDC1"
        Id          = 4769
        TimeCreated = $(Get-Date)
        Properties  = @(
            @{Value = 'KDC$@CONTOSO.COM' }
            @{Value = 'CONTOSO.COM' }
            @{Value = 'KDC2$' }
            @{Value = 'S-1-5-21-2525879430-3093583400-2026621138-1105' }
            @{Value = '1082195968' }
            @{Value = '18' }
            @{Value = '::1' }
            @{Value = '0' }
            @{Value = '0' }
            @{Value = 'ad136b76-daa7-8e25-31d7-3f2e21df6a36' }
            @{Value = '-' }
            @{Value = 'vs+nolPjeVqyWyaMVz3dW/K/EmUqQy15MW0qP+rijVY=' }
            @{Value = 'fJI8TXEUFCezq+zYhyKW4vggnQS+eaiaHXPAXIeqoDY=' }
            @{Value = 'N/A' }
            @{Value = 'N/A' }
            @{Value = '0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)' }
            @{Value = 'AES128-SHA96, AES256-SHA96, RC4' }
            @{Value = '0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)' }
            @{Value = 'AES-SHA1, RC4' }
            @{Value = '...' }
            @{Value = '18' }
        )
    }

    $script:RC4_4769_EVENT = [PSCustomObject]@{
        RecordId    = 1
        MachineName = "KDC1"
        Id          = 4769
        TimeCreated = $(Get-Date)
        Properties  = @(
            @{Value = 'KDC$@CONTOSO.COM' }
            @{Value = 'CONTOSO.COM' }
            @{Value = 'KDC2$' }
            @{Value = 'S-1-5-21-2525879430-3093583400-2026621138-1105' }
            @{Value = '1082195968' }
            @{Value = '23' }
            @{Value = '::1' }
            @{Value = '0' }
            @{Value = '0' }
            @{Value = 'ad136b76-daa7-8e25-31d7-3f2e21df6a36' }
            @{Value = '-' }
            @{Value = 'vs+nolPjeVqyWyaMVz3dW/K/EmUqQy15MW0qP+rijVY=' }
            @{Value = 'fJI8TXEUFCezq+zYhyKW4vggnQS+eaiaHXPAXIeqoDY=' }
            @{Value = 'N/A' }
            @{Value = 'N/A' }
            @{Value = '0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)' }
            @{Value = 'AES-SHA1, RC4' }
            @{Value = '0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)' }
            @{Value = 'AES-SHA1, RC4' }
            @{Value = '...' }
            @{Value = '18' }
        )
    }

    $script:AES_4768_EVENT = [PSCustomObject]@{
        RecordId    = 1
        MachineName = "KDC1"
        Id          = 4768
        TimeCreated = $(Get-Date)
        Properties  = @(
            @{ Value = "KDC$" }
            @{ Value = "contoso.com" }
            @{ Value = "S-1-5-21-2525879430-3093583400-2026621138-1002" }
            @{ Value = "krbtgt" }
            @{ Value = "S-1-5-21-2525879430-3093583400-2026621138-502" }
            @{ Value = "1082195984" }
            @{ Value = "0" }
            @{ Value = "18" }
            @{ Value = "2" }
            @{ Value = "::1" }
            @{ Value = "0" }
            @{ Value = "" }
            @{ Value = "" }
            @{ Value = "" }
            @{ Value = "iE2YRlHzQ+Ri39mHBPcbMlBb1N3EACnC/EbE6QRV/Jg=" }
            @{ Value = "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)" }
            @{ Value = "AES-SHA1, RC4" }
            @{ Value = "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)" }
            @{ Value = "AES-SHA1, RC4" }
            @{ Value = "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)" }
            @{ Value = "AES-SHA1, RC4" }
            @{ Value = "..." }
            @{ Value = "18" }
            @{ Value = "18" }
        )
    }

    $script:RC4_4768_EVENT = [PSCustomObject]@{
        RecordId    = 1
        MachineName = "KDC1"
        Id          = 4768
        TimeCreated = $(Get-Date)
        Properties  = @(
            @{ Value = "KDC$" }
            @{ Value = "contoso.com" }
            @{ Value = "S-1-5-21-2525879430-3093583400-2026621138-1002" }
            @{ Value = "krbtgt" }
            @{ Value = "S-1-5-21-2525879430-3093583400-2026621138-502" }
            @{ Value = "1082195984" }
            @{ Value = "0" }
            @{ Value = "23" }
            @{ Value = "2" }
            @{ Value = "::1" }
            @{ Value = "0" }
            @{ Value = "" }
            @{ Value = "" }
            @{ Value = "" }
            @{ Value = "iE2YRlHzQ+Ri39mHBPcbMlBb1N3EACnC/EbE6QRV/Jg=" }
            @{ Value = "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)" }
            @{ Value = "AES-SHA1, RC4" }
            @{ Value = "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)" }
            @{ Value = "AES-SHA1, RC4" }
            @{ Value = "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)" }
            @{ Value = "AES-SHA1, RC4" }
            @{ Value = "..." }
            @{ Value = "18" }
            @{ Value = "18" }
        )
    }

    $script:KDCs = @(
        [PSCustomObject]@{
            HostName = "KDC1"
        }
        [PSCustomObject]@{
            HostName = "KDC2"
        }
        [PSCustomObject]@{
            HostName = "KDC3"
        }
    )

    function Get-ADDomainController {
        return $script:KDCs
    }

}


Describe 'Get-KerbEncryptionUsage.ps1' {

    BeforeAll {
        . $PSScriptRoot\Get-KerbEncryptionUsage.ps1
    }

    It 'contain kerberos encryption types' {
        $result = Get-EncryptionTypes
        $result | Should -Not -BeNullOrEmpty
        $result.Count | Should -Be 8
    }

    It 'should return RC4 for 0x17' {
        $result = Get-EncryptionType -Value 0x17 -Debug
        $result.Name | Should -Be "RC4"
    }

    It 'should return 0x17 for RC4' {
        $result = Get-EncryptionType -Name "RC4"
        $result.Value | Should -Be 0x17
    }

    It 'should return an unknown value for an unknown name' {
        Get-EncryptionType -Name "Lorem Ipsum" | Should -Be "Unknown"
    }

    It 'should return record with AES usage' {
        Mock Get-WinEvent {
            return $script:AES_4769_EVENT
        }

        $result = Get-KerbEncryptionUsage
        $result.Count | Should -Be 1
        $result.Ticket | Should -Be "AES256-SHA96"
        $result.SessionKey | Should -Be "AES256-SHA96"
    }

    It 'should only return an RC4 usage' {
        Mock Get-WinEvent {
            return $script:AES_4769_EVENT, $script:RC4_4769_EVENT
        }

        $result = Get-KerbEncryptionUsage -Encryption "RC4"
        $result.Count | Should -Be 1
        $result.Ticket | Should -Be "RC4"
        $result.SessionKey | Should -Be "AES256-SHA96"
    }

    It 'should an event from KDC1 and KDC 3' {
        $script:count = 0

        Mock Get-WinEvent {
            $kdc = $PesterBoundParameters.ComputerName
            $expectedKdc = $script:KDCs[$script:count].HostName

            $kdc | Should -Be $expectedKdc
            $script:count += 1

            if ($script:count -eq 2) {
                return $null
            }
            else {
                return $script:AES_4769_EVENT
            }
        }

        $result = Get-KerbEncryptionUsage -SearchScope AllKdcs
        $script:count | Should -Be 3
        $result.Count | Should -Be 2
    }

    It 'should only return events with AES ticket encryption' {
        Mock Get-WinEvent {
            return $script:AES_4769_EVENT, $script:RC4_4769_EVENT, $script:AES_4768_EVENT, $script:RC4_4768_EVENT
        }

        $results = Get-KerbEncryptionUsage -Encryption "AES-SHA1" -EncryptionUsage "Ticket"
        $results.Count | Should -Be 2
    }

    It 'should only return events with RC4 SK usage' {
        Mock Get-WinEvent {
            return $script:AES_4769_EVENT, $script:RC4_4769_EVENT, $script:AES_4768_EVENT, $script:RC4_4768_EVENT
        }

        $results = Get-KerbEncryptionUsage -Encryption "RC4" -EncryptionUsage "SessionKey"
        $results.Count | Should -Be 0
    }

    It 'should only return events with AES usage for ticket encryption and sk encryption' {
        Mock Get-WinEvent {
            return $script:AES_4769_EVENT, $script:RC4_4769_EVENT, $script:AES_4768_EVENT, $script:RC4_4768_EVENT
        }

        $results = Get-KerbEncryptionUsage -Encryption "AES-SHA1" -EncryptionUsage "Both"
        $results.Count | Should -Be 2
    }
}

Describe 'List-AccountKeys.ps1' {
    BeforeAll {
        . $PSScriptRoot\List-AccountKeys.ps1
    }

    It 'should return service all accounts keys' {
        Mock Get-WinEvent {
            return $script:AES_4769_EVENT
        }

        $result = List-AccountKeys
        $result.Count | Should -Be 1
        $result[0].Keys | Should -Match "RC4"
        $result[0].Keys | Should -Match "AES128-SHA96"
        $result[0].Keys | Should -Match "AES256-SHA96"
    }

    It 'should correctly parse the new key format' {
        Mock Get-WinEvent {
            return $script:4769_NEW_FORMAT
        }

        $result = List-AccountKeys
        $result.Count | Should -Be 1
        $result[0].Keys | Should -Match "RC4"
        $result[0].Keys | Should -Match "AES128-SHA96"
        $result[0].Keys | Should -Match "AES256-SHA96"
    }

    It 'should correctly return keys in multiple formats from multiple kdcs' {
        $script:count = 0

        Mock Get-WinEvent {
            $script:count += 1
            if ($script:count -eq 2) {
                return $script:4769_NEW_FORMAT
            }
            else {
                return $script:AES_4769_EVENT, $script:RC4_4769_EVENT
            }
        }

        $results = List-AccountKeys -SearchScope AllKdcs

        $script:count | Should -Be 3
        $results.Count | Should -Be 5
    }

    Context 'ContainsKeyType filtering on Server 2022 (AES-SHA1 filter)' {
        BeforeAll {
            $script:OriginalAESFilter = $script:AES_SHA1_FILTER
            $script:AES_SHA1_FILTER = $script:AES_SHA1_FILTER_2022
        }

        BeforeEach {
            $script:KeyFilter = ""
            $script:NotKeyFilter = ""
        }

        AfterAll {
            $script:AES_SHA1_FILTER = $script:OriginalAESFilter
        }

        It 'should return events whose account supported keys contain AES-SHA1' {
            Mock Get-WinEvent {
                return $script:AES_4769_EVENT, $script:RC4_4769_EVENT
            }

            $results = List-AccountKeys -ContainsKeyType "AES-SHA1"
            $results.Count | Should -Be 2
            $results | ForEach-Object {
                $_.Keys | Should -Match "AES"
            }
        }

        It 'should exclude events whose account supported keys contain AES-SHA1' {
            Mock Get-WinEvent {
                return $script:AES_4769_EVENT, $script:RC4_4769_EVENT
            }

            $results = List-AccountKeys -NotContainsKeyType "AES-SHA1"
            $results.Count | Should -Be 0
        }
    }

    Context 'ContainsKeyType filtering on Server 2025 (SHA96 filter)' {
        BeforeAll {
            $script:OriginalAESFilter = $script:AES_SHA1_FILTER
            $script:AES_SHA1_FILTER = $script:AES_SHA1_FILTER_2025
        }

        BeforeEach {
            $script:KeyFilter = ""
            $script:NotKeyFilter = ""
        }

        AfterAll {
            $script:AES_SHA1_FILTER = $script:OriginalAESFilter
        }

        It 'should return events whose account supported keys contain SHA96 in new format' {
            Mock Get-WinEvent {
                return $script:4769_NEW_FORMAT
            }

            $results = List-AccountKeys -ContainsKeyType "AES-SHA1"
            $results.Count | Should -Be 1
            $results[0].Keys | Should -Match "AES128-SHA96"
            $results[0].Keys | Should -Match "AES256-SHA96"
        }

        It 'should exclude events whose account supported keys contain SHA96' {
            Mock Get-WinEvent {
                return $script:4769_NEW_FORMAT
            }

            $results = List-AccountKeys -NotContainsKeyType "AES-SHA1"
            $results.Count | Should -Be 0
        }

        It 'should not match old-format AES-SHA1 string when filter is SHA96' {
            # On 2025, old-format "AES-SHA1" events do NOT contain "SHA96",
            # so they should be excluded by ContainsKeyType "AES-SHA1"
            Mock Get-WinEvent {
                return $script:AES_4769_EVENT
            }

            $results = List-AccountKeys -ContainsKeyType "AES-SHA1"
            $results.Count | Should -Be 0
        }
    }
}