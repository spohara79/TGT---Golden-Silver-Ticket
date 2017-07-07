<#
    .SYNOPSIS
        List potential golden and silver kerberos tickets
    .DESCRIPTION
        Potential golden and silver tickets are written to event log, where the tickets are compared to the configured max-age ticket
    .PARAMETER MaxAge
        MaxAge is a [TimeSpan] object that represents the maximum age of kerberos tickets defined in the domain policy
    .PARAMETER SourceName
        SourceName is an optional parameter that specifies the name of the application the event is written
    .PARAMETER EventId
        EventId is a optional comma separated pair of event IDs <golden event id, silver event id> (one for golden and one for silver); this defaults to 3001 and 3002
        E.g. 42001,42002 where the golden event id is 42001 and the silver event id is 42002
#>
 
[CmdletBinding()]
 
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [TimeSpan]$MaxAge,
    [Parameter(Mandatory=$False)]
    [string]$SourceName,
    [Parameter(Mandatory=$False)]
    [ValidatePattern('^\d+\s\d+')]
    [string]$EventId
)

If (!$EventId) {
    $EventIdGolden = 3001
    $EventIdSilver = 3002
} Else {
    $EventIdGolden, $EventIdSilver = $EventId.Split(' ', 2)
}

If (!$SourceName) {
    $SourceName = "TGT Tickets"
}
 
$kerberosHash = @{}
 
function Get-KerberosSessions {
    $KerberosSessions = Get-WmiObject Win32_LogonSession
    foreach ($kerbSession in $KerberosSessions) {
        $kObject = New-Object PSObject -Property @{
            'SessionID'='0x{0:x}' -f ([int] $kerbSession.LogonID)
            'LogonType'=$kerbSession.LogonType
            'AuthPackage'=$kerbSession.AuthenticationPackage
        }
        $kerberosHash.($kObject.SessionID) = $kObject
    }
    #return $kerberosHash
}
 
function Search-GoldenTicketFromSession {
    param($sessionId, $compareTime)
    $tgtLowPart = klist.exe tgt -li $sessionId
 
    Try {
        $__, $startTime = $tgtLowPart[15].Split(':', 2)
    }
    Catch [System.Management.Automation.RuntimeException] {
        return $False
    }
    [DateTime]$GTStartTime = $startTime.Substring(1, $startTime.Length-9)
    $__, $endTime = $tgtLowPart[16].Split(':', 2)
    [DateTime]$GTEndTime = $endTime.Substring(1, $endTime.Length-9)
    $__, $renewTime = $tgtLowPart[17].Split(':', 2)
    [DateTime]$GTRenewTime = $renewTime.Substring(1, $renewTime.Length-9)
 
    If (($GTEndTime - $GTStartTime) -gt $compareTime) {
        $kerbObject = $kerberosHash.($sessionId)
        $newKerbObject = New-Object PSObject -Property @{
            "SessionID" = $kerbObject.SessionID
            "LogonType" = $kerbObject.LogonType
            "AuthPackage" = $kerbObject.AuthPackage
            "ServiceName" = $tgtLowPart[6].Split(':',2)[1].Substring(1)  # ServiceName
            "TargetName" = $tgtLowPart[7].Split(':',2)[1].Substring(1)  # TargetName (SPN)
            "ClientName" = $tgtLowPart[8].Split(':',2)[1].Substring(1)  # ClientName
            "DomainName" = $tgtLowPart[9].Split(':',2)[1].Substring(1)  # DomainName
            "TicketFlags" = $tgtLowPart[12].Split(':',2)[1].Substring(1)  # TicketFlags
            "StartTime" = $GTStartTime
            "EndTime" = $GTEndTime
            "RenewTime" = $GTRenewTime
        }
        return $newKerbObject
    } else {
        return $False
    }
}
 
function Search-SilverTicketFromSession {
    param($sessionId, $compareTime)
    $SilverTickets = @()
    $ticketLowPart = klist.exe tickets -li $sessionId
    $lineCount = 0
    foreach ($line in $ticketLowPart) {
        if ($line -match '#\d+>') {
            Try {
                $__, $startTime = $ticketLowPart[$lineCount+4].Split(':', 2)
            }
            Catch [System.Management.Automation.RuntimeException] {
                return $False  
            }
            [DateTime]$GTStartTime = $startTime.Substring(1, $startTime.Length-9)
            $__, $endTime = $ticketLowPart[$lineCount+5].Split(':', 2)
            [DateTime]$GTEndTime = $endTime.Substring(1, $endTime.Length-9)
            $__, $renewTime = $ticketLowPart[$lineCount+6].Split(':', 2)
            [DateTime]$GTRenewTime = $renewTime.Substring(1, $renewTime.Length-9)
 
            If (($GTEndTime - $GTStartTime) -gt $compareTime) {
                $kerbObject = $kerberosHash.($sessionId)
                $newKerbObject = New-Object PSObject -Property @{
                    "SessionID" = $kerbObject.SessionID
                    "LogonType" = $kerbObject.LogonType
                    "AuthPackage" = $kerbObject.AuthPackage
                    "Client" = $line.Split(':',2)[1].Substring(1)
                    "Server" = $ticketLowPart[$lineCount+1].Split(':',2)[1].Substring(1)
                    "EncryptionType" = $ticketLowPart[$lineCount+2].Split(':',2)[1].Substring(1)
                    "TicketFlags" = $ticketLowPart[$lineCount+3].Substring(14)
                    "SessionKeyType" = $ticketLowPart[$lineCount+7].Split(':',2)[1].Substring(1)
                    "StartTime" = $GTStartTime
                    "RenewTime" = $GTRenewTime
                }
                $SilverTickets += $newKerbObject
            }
        }
        $lineCount++
    }
    if ($SilverTickets) {
        return $SilverTickets
    } Else {
        return $False
    }
}
 
 
# Stolen from jeffmurr.com/blog/?p=231
function Write-TicketToLog {
    param($EventId, $logMessage)
    
    $ErrorActionPreference = "SilentlyContinue"
    If (!(Get-Eventlog -LogName Application -Source $SourceName)) {
        $ErrorActionPreference = "Continue"
        Try {
            New-Eventlog -LogName Application  -Source $SourceName | Out-Null
        }
        Catch [System.Security.SecurityException] {
            Write-Error "Error:  Run as elevated user.  Unable to write or read to event logs."
        }
    }
    Try {
        Write-EventLog -LogName Application -Source $SourceName -EntryType Warning -EventId $EventId -Message $logMessage
    }
    Catch [System.Security.SecurityException] {
        Write-Error "Error:  Run as elevated user.  Unable to write to event logs."
    }
}
 
Get-KerberosSessions
foreach ($kArray in $kerberosHash.GetEnumerator()) {
    $searchGolden = Search-GoldenTicketFromSession $kArray.Name $MaxAge.Hours
    if ($searchGolden -ne $False) {
        $goldenTicket = $searchGolden | Out-String
        Write-TicketToLog $EventIdGolden "Possible Golden Ticket(s): $($goldenTicket)"
    }
    $searchSilver = Search-SilverTicketFromSession $kArray.Name $MaxAge.Hours
    if ($searchSilver -ne $False) {
        $silverTickets = $searchSilver| Out-String
        Write-TicketToLog $EventIdSilver "Possible Silver Ticket(s): $($silverTickets)"
    }
}
