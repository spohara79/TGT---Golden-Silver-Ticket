function Get-KerberosMaxTicketAge {
    #Requires -modules GroupPolicy
    [CmdletBinding()]
    [OutputType([TimeSpan])]
    Param()
    Begin {
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
        Try {
            [xml]$DefaultDomainPolicy = Get-GPOReport -Guid '{31B2F340-016D-11D2-945F-00C04FB984F9}' -ReportType Xml
            $DDPSecurityNodes = ($DefaultDomainPolicy.GPO.Computer.ExtensionData | Where-Object {$_.Name -eq 'Security'}).Extension.ChildNodes
            [int]$maxTicketAge = ($DDPSecurityNodes | Where-Object {$_.Name -eq 'MaxTicketAge'}).SettingNumber
        }
        Catch {
            $catchMessage = "Unable to retrieve policy. Defaulting to 10 hours."
            Write-Debug $catchMessage
            [int]$maxTicketAge = 10
        }
        Write-Verbose "maxTicketAge: $($maxTicketAge.toString())"
    }
    Process {
        $maxTicketAgeTimeSpan = New-TimeSpan -Hours $maxTicketAge
        $maxAgeMessage = "TGT Max Ticket Age: $($maxTicketAgeTimeSpan.toString())"
        Write-Verbose -Message $maxAgeMessage
        $maxTicketAgeTimeSpan
    }
}
