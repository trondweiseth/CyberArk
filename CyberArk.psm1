<# .SYNOPSIS

    PSS CyberArk Module 

.DESCRIPTION

     Module to interact with CyberArk
     Commands:
     
       PSS-RDPSession        : Opens RDP session to host(s) through CyberArk
       PSS-GetRequest        : Getting a list of requests
       PSS-RemoveRequest     : Removes request(s)
       PSS-ApproveRequest    : Approves Request(s)
       PSS-NewRequest        : Creating request(s)
       PSS-Host              : Search for hostname(s)
       PSS-DualControlCheck  : Checking if 4-eyes is required
       PSS-RemoteHost        : Looking up remote server(s)
       PSS-AddSafe           : Creating new safe(s) and adding Administrator.
       PSS-GetMemberSafes    : Fetching all safes that a member(user) is a member of
       PSS-UnlockUser        : Unlocking local CyberArk users
       PSS-GetGroupMembers   : List members of CyberArk groups
       PSS-GetSafeMembers    : List members of a safe
       PSS-GetGroups         : List CyberArk groups


.NOTES
     Author     : Trond Weiseth
#>

# Setting global variables and running checks:
$Global:domain                  = "$env:USERDNSDOMAIN" # Set the login domain for pvwa
$Global:Type                    = "LDAP" # CyberArk login type. LDAP or cyberark.
$Global:README                  = "This is files that the CyberArk Powershell module uses to auto-complete parameters. PS! Do not modify or delete!" # Creates a README file where usernames, hostnames and platforms are stored at.
$Global:ScriptTextFilesLocation = "<PATH>" # Set location where usernames, hostnames and platforms are stored.
if ($false -eq $(Test-Path $ScriptTextFilesLocation)) {New-Item -Type Directory "$ScriptTextFilesLocation" ; UpdateLists}
$Global:CurrentDate             = Get-Date
$Global:FileDate                = (Get-Item "${ScriptTextFilesLocation}\Username.txt").LastWriteTime
$Global:DaysDiff                = ($currentdate - $filedate).Days
if ($DaysDiff -gt 30)             {ValidateSession ; UpdateLists}
$Global:BaseURI                 = '<SERVERNAME>' # Set the pvwa server
$Global:PSSServerEnv            = Get-Content "${ScriptTextFilesLocation}\psshostlist.txt"
$Global:PlatformIDs             = Get-Content "${ScriptTextFilesLocation}\Platform.txt"
$Global:PSSUserNames            = Get-Content "${ScriptTextFilesLocation}\Username.txt"
$Global:Resolution              = @(
    '1024x800'
    '1280x1024'
    '1366x768'
    'FullScreen'
)

# Errorhandling
Function psserrorhandling {
    $exec_ok = $false
    if     ($Global:Error[0] -imatch "There is no confirmed request for this account"                                  ) { Write-Host -f Red -b Black "There is no confirmed request for this account: $C" ; return }
    elseif ($Global:Error[0] -imatch "You are not authorized to perform this action"                                   ) { Write-Host -f Red -b Black "Host: $C : You are not authorized to perform this action"    }
    elseif ($Global:Error[0] -imatch "Cannot validate argument on parameter 'RequestId'. The argument is null or empty") { Write-Host -f Red -b Black "No request ID found"                                         }
    elseif ($Global:Error[0] -imatch "Authentication failure"                                                          ) { Write-Host -f Red -b Black "Authentication failure" ; AddCredentials                     }
    elseif ($Global:Error[0] -imatch "Run New-PASSession"                                                              ) { CyberArkSession                                                                          }
    elseif ($Global:Error[0] -imatch "has been disconnected"                                                           ) { CyberArkSession                                                                          }
    elseif ($Global:Error[0] -imatch "Logoff from the Vault and logon again"                                           ) { Close-PASSession ; CyberArkSession                                                       }
    elseif ($Global:Error[0] -imatch "logged off"                                                                      ) { CyberArkSession                                                                          }
    elseif ($Global:Error[0] -imatch "password"                                                                        ) { Write-Host -f Red -b Black "Missing password!" ; AddCredentials                          }
    elseif ($Global:Error[0] -imatch "has been suspended"                                                              ) { break                                                                                    }
    elseif ($Global:Error[0] -imatch "Cannot validate argument on parameter 'RequestId'. The argument is null or empty") { Write-Host -f Red -b Black "No request ID found"                                         }
    elseif ($Global:Error[0] -imatch "No request is needed for object"                                                 ) { Write-Host -f Red -b Black "No request is needed for $C" ; return                        }
    elseif ($Global:Error[0] -imatch "This request has already been closed"                                            ) { Write-Host -f Red -b Black "This request has already been closed"                        }
    else                                                                                                                 { Write-Host -f Red -b Black "Unknown error:"  ; Write-Host $Global:Error                  }
    $Global:Error.Remove($Global:Error)
}

# Get pscredentials for CyberArk login
Function AddCredentials {
    
    Try {
        $Global:PSScred = Get-Credential -UserName "$($env:USERNAME)@$domain" -Message "Please input Cyberark credentials for PSS" -ErrorAction Stop
        $Global:PSSUserName = $PSScred.UserName.Split("@")[0]
        CyberArkSession
    }
    Catch {
        if (!$PSScred) {break}
        if (!$PSScred.GetNetworkCredential().Password) { Write-Host -f Red -b Black "Missing credentials!" ; AddCredentials }
    }
}

# Checking if pscredentials for CyberArk is stored and connects user to CyberArk
Function CyberArkSession {


    if (!$PSScred) { AddCredentials }
  <# If you have a test enviroment and have different xredentials for it, you can set it here and dubplicate for each enviroment
    if ($ComputerName -imatch "pvwa-test") {
        $Global:BaseURI = "<SERVERNAME_FOR_TEST>"
    }
  #>
    if ($PSSUserName -imatch 'administrator') {
        $uname = $PSSUserName
    }
    else {
        $uname = ("$($PSSUserName)@$domain")
    }

    $Global:PSScred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname, $PSScred.Password

    try {
        if ($uname -imatch 'administrator') {
            New-PASSession -Credential $PSScred -BaseURI $BaseURI -ErrorAction Stop
        }
        else {
            New-PASSession -Credential $PSScred -BaseURI $BaseURI -type $Type -ErrorAction Stop
        }
        Test-Path ${ScriptTextFilesLocation}\Username.txt, ${ScriptTextFilesLocation}\Platform.txt, ${ScriptTextFilesLocation}\psshostlist.txt | % { if ($_ -eq $false) {UpdateLists} }
    }
    catch {
        psserrorhandling
    }
}

# Checking if user is logged in and connected to CybeArk
Function ValidateSession {

    $error.Clear()
    if ($null -eq (Get-PASSession -ErrorAction Stop).user) {
        CyberArkSession
    }

    CheckForModifiedFiles
}

Function UpdateLists() {
    write-host "Updating usernames and hosts list.."
    Get-PASAccount  | Select-Object -ExpandProperty username -Unique   | Out-File ${ScriptTextFilesLocation}\Username.txt
    Get-PASPlatform | Select-Object -ExpandProperty PlatformID -Unique | Out-File ${ScriptTextFilesLocation}\Platform.txt
    Get-PASAccount  | Select-Object -ExpandProperty address -Unique    | Out-File ${ScriptTextFilesLocation}\psshostlist.txt
    $Hostlist = Get-Content ${ScriptTextFilesLocation}\psshostlist.txt
    $h = (Get-PASAccount  | where-object { $_.remoteMachinesAccess } | select -ExpandProperty remoteMachinesAccess | Select -ExpandProperty remotemachines -Unique).split(';')
    Compare-Object -ReferenceObject $h -DifferenceObject $Hostlist | where {$_.sideindicator -ne '=>'} | select -ExpandProperty inputobject | Out-File ${ScriptTextFilesLocation}\psshostlist.txt -Append
    $README | Out-File ${ScriptTextFilesLocation}\README.txt
    $NewHash = (Get-FileHash  -Algorithm RIPEMD160 "${ScriptTextFilesLocation}\*" | where {$_ -notmatch "CheckSum.txt"}).hash 
    [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($NewHash)) | Out-File ${ScriptTextFilesLocation}\CheckSum.txt
    write-host "Done updating."
}

Function CheckForModifiedFiles() {
    $Global:CheckSum        = Get-content "${ScriptTextFilesLocation}\CheckSum.txt"
    $Global:CurrentFileHash = (Get-FileHash  -Algorithm RIPEMD160 "${ScriptTextFilesLocation}\*" | where {$_ -notmatch "CheckSum.txt"}).hash
    $Global:OldFileHash     = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($checksum)).Split(' ')
    if (diff $CurrentFileHash $OldFileHash) {UpdateLists}
}

# This function is for connecting to a server with RDP or SSH
Function PSS-RDPSession {

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $PssHostName = $PSSServerEnv | Where-Object -FilterScript { $_ -imatch $wordToComplete }
                return $PssHostName
            } )]
        [string[]]
        $ComputerName,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $PssUserName = $PssUserNames | Where-Object -FilterScript { $_ -imatch $wordToComplete }
                return $PssUserName
            } )]
        [string]
        $Username,

        [parameter(Mandatory = $false)]
        [switch]$HostList,

        [parameter(Mandatory = $false)]
        [string]
        $HostFile,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $ScreenRes = $Resolution | Where-Object -FilterScript { $_ -imatch $wordToComplete }
                return $ScreenRes
            } )]
        [string]
        $ScreenResolution = '1280x1024',

        [Parameter(Mandatory = $false)]
        [switch]
        $AllowMappingLocalDrives,

        [Parameter(Mandatory = $false)]
        [string]
        $Reason
    )

    Begin {
        ValidateSession
        $Global:ComputerName = $ComputerName
        
        if ($AllowMappingLocalDrives) {
            $AMLD = 'Yes'
        }
        else {
            $AMLD = 'No'
        }

        if ($HostList) {
            hostlistbox
        }

        if ($HostFile) {
            $res = Test-Path $HostFile

            if ($res = $true) {
                $Global:ComputerName = (Get-Content $HostFile)
            }
            else {
                Write-warning "Could not find the path or file."
            }
            
        }

        function main_RDPSession {
            $AccountID   = $PASAccount.id
            $Plattform   = $PASAccount.platformId
            $AccountName = $PASAccount.name

            if ($Plattform -imatch 'WIN'                                             ) { $CM = 'RDP'   ; $CC = 'PSM-RDP'              }
            if ($Plattform -imatch 'VMWARE'                                          ) { $CM = 'PSMGW' ; $CC = 'PSM-VSPHERE-Web'      }
            if ($Plattform -imatch 'LINUX' -or $Plattform -imatch 'UNIX'             ) { $CM = 'PSMGW' ; $CC = 'PSM-SSH-BF'           }
            if ($Plattform -imatch 'LINUX' -and $AccountName -imatch 'pss-cap-pta1'  ) { $CM = 'PSMGW' ; $CC = 'PSM-SSH'              }
            if ($Plattform -imatch 'LenovoLXCC'                                      ) { $CM = 'PSMGW' ; $CC = 'PSM-LenovoLXCC'       }
            if ($Plattform -imatch 'Cyberark'                                        ) { $CM = 'PSMGW' ; $CC = 'PSM-PrivateArkClient' }
            if ($Plattform -imatch 'CyberArkPTA'                                     ) { $CM = 'PSMGW' ; $CC = 'PSM-PTA'              }

            if ($PASAccount.remoteMachinesAccess) {
                try {
                    [string]$RemoteMachine = ($PASAccount.remoteMachinesAccess.remoteMachines.Split(";") | where {$_ -imatch $C} | sort -Unique)
                    New-PASPSMSession -AccountID $AccountID -PSMRemoteMachine $RemoteMachine -ConnectionMethod $CM -ConnectionComponent $CC -AllowMappingLocalDrives $AMLD -reason $Reason |
                    Tee-Object -Variable RDPSessionFile -ErrorAction Stop
                    $exec_ok = $true
                }
                catch {
                    psserrorhandling
                }
            }

            else {
                try {
                    New-PASPSMSession -AccountID $AccountID -ConnectionMethod $CM -ConnectionComponent $CC -reason $Reason -AllowMappingLocalDrives $AMLD | Tee-Object -Variable RDPSessionFile -ErrorAction Stop
                    $exec_ok = $true
                }
                catch {
                    psserrorhandling
                }
            }
            
            if ($exec_ok) {
                $FilePath = $RDPSessionFile | Select-Object -ExpandProperty DirectoryName
                $FileName = $RDPSessionFile | Select-Object -ExpandProperty name
                
                if ($Plattform -imatch 'WIN') {
                    if ($ScreenResolution -eq "FullScreen") {
                        mstsc /f $FilePath/$FileName
                    }
                    elseif ($ScreenResolution -notmatch "x" -and $ScreenResolution -notmatch "FullScreen") {
                        $current_vc            =      (Get-DisplayResolution|Out-String               )
                        $current_vc            =      ($current_vc -replace '[\u0000]',''             )
                        $current_vc_Horizontal = [int]($current_vc.split("x")[0]                      )
                        $current_vc_Vertical   = [int]($current_vc.split("x")[1]                      )
                        $W                     = [int]($current_vc_Horizontal*($ScreenResolution/100) )
                        $H                     = [int]($current_vc_Vertical*($ScreenResolution/100)   )
                        mstsc /w:$W /h:$H $FilePath/$FileName
                    }
                    else {
                        $W = $ScreenResolution.Split('x')[0]
                        $H = $ScreenResolution.Split('x')[1]
                        mstsc /w:$W /h:$H $FilePath/$FileName
                    }
                }

                elseif ($Plattform -imatch 'LINUX' -or $Plattform -imatch 'UNIX' -or $Plattform -imatch 'VMWARE' -or $Plattform -imatch 'LenovoLXCC' -or $Plattform -imatch 'Cyberark') {
                    mstsc $FilePath/$FileName
                }
                else {
                    Write-Host "Platform $Plattform don't match Linux, Windows, VMware or LenovoLXCC"
                }
            }
        }
    }

    Process {
        foreach ($Global:C in $ComputerName) {
            $PASAccounts  = $(Get-PASAccount | where { $_.address -imatch $C };Get-PASAccount | where { $_.remoteMachinesAccess -imatch $C })
 
            if (!$Username) {
                $Selection = $PASAccounts | Select-Object address, username, name | Out-GridView -Title "Accounts" -PassThru
                foreach ($Account in $Selection) {
                    $Global:PASAccount = $PASAccounts | Where-Object { $_.address -imatch $Account.address -and $_.username -imatch $Account.userName }
                    main_RDPSession
                }

            }
            else {
                $PASAccount = $PASAccounts | Where-Object { $_.address -imatch $Account.address -and $_.username -imatch $Username }
                main_RDPSession
            }
        }
    }

    End {}
}

# Getting request(s) in CyberArk
Function PSS-GetRequest {

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $false, HelpMessage = "Valid RequestType: IncomingRequests or MyRequests")]
        [ValidateSet('IncomingRequests', 'MyRequests')]
        [string]
        $RequestType = 'IncomingRequests',

        [parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [string]
        $OnlyWaiting = 'Yes',

        [parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [string]
        $Expired = 'No'
    )

    Begin {
        if ($OnlyWaiting -eq 'Yes') { $owa = 1 } else { $owa = 0 }
        if ($Expired     -eq 'Yes') { $exp = 1 } else { $exp = 0 }
        ValidateSession
    }

    Process {
        try {
            $Requests = Get-PASRequest -RequestType $RequestType -OnlyWaiting $owa -Expired $exp -ErrorAction Stop | 
            Select-Object RequestID, Operation, RequestorUserName,
            @{ Name = 'CreationDate'  ; Expression = { $time = (([System.DateTimeOffset]::FromUnixTimeSeconds($_.CreationDate)).DateTime).ToString()   ; (Get-date $time).AddHours(2) } },
            @{ Name = 'ExpirationDate'; Expression = { $time = (([System.DateTimeOffset]::FromUnixTimeSeconds($_.ExpirationDate)).DateTime).ToString() ; (Get-date $time).AddHours(2) } },
            @{ Name = 'AccessFrom'    ; Expression = { $time = (([System.DateTimeOffset]::FromUnixTimeSeconds($_.AccessFrom)).DateTime).ToString()     ; (Get-date $time).AddHours(2) } },
            @{ Name = 'AccessTo'      ; Expression = { $time = (([System.DateTimeOffset]::FromUnixTimeSeconds($_.AccessTo)).DateTime).ToString()       ; (Get-date $time).AddHours(2) } },
            AccessType, ConfirmationsLeft, RequestorReason | 
            Out-GridView -Title "Requests" -PassThru
            $Requests | Format-Table -AutoSize -Wrap
        }
        catch {
            psserrorhandling
        }
    }

    End {}
}

# Removes request(s) in CyberArk
Function PSS-RemoveRequest {

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $false, HelpMessage = "Valid RequestType: IncomingRequests or MyRequests")]
        [ValidateSet('IncomingRequests', 'MyRequests')]
        [string]
        $RequestType = 'IncomingRequests',

        [parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [string]
        $OnlyWaiting = 'Yes',

        [parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [string]
        $Expired = 'No'
    )

    Begin {
        if ($OnlyWaiting -eq 'Yes') { $owa = 1 } else { $owa = 0 }
        if ($Expired     -eq 'Yes') { $exp = 1 } else { $exp = 0 }
        ValidateSession
    }

    Process {
        try {
            $Requests = Get-PASRequest -RequestType $RequestType -OnlyWaiting $owa -Expired $exp -ErrorAction Stop | 
            Select-Object RequestID, Operation, RequestorUserName,
            @{ Name = 'CreationDate'  ; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.CreationDate))   } },
            @{ Name = 'ExpirationDate'; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.ExpirationDate)) } },
            @{ Name = 'AccessFrom'    ; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.AccessFrom))     } },
            @{ Name = 'AccessTo'      ; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.AccessTo))       } },
            AccessType, ConfirmationsLeft, RequestorReason | 
            Out-GridView -Title "Requests" -PassThru
            $Requests | Format-Table -AutoSize -Wrap
            $RequestID = $Requests.requestid

            foreach ($ID in $RequestID) {
                Remove-PASRequest -RequestID $ID
            }
        }
        catch {
            psserrorhandling
        }
    }

    End {}
}

# Deny request(s) in CyberArk
Function PSS-DenyRequest {

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $false, HelpMessage = "Valid RequestType: IncomingRequests or MyRequests")]
        [ValidateSet('IncomingRequests', 'MyRequests')]
        [string]
        $RequestType = 'IncomingRequests',

        [parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [string]
        $OnlyWaiting = 'Yes',

        [parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [string]
        $Expired = 'No',

        [Parameter(Mandatory = $false)]
        [string]
        $Reason
    )

    Begin {
        if ($OnlyWaiting -eq 'Yes') { $owa = 1 } else { $owa = 0 }
        if ($Expired     -eq 'Yes') { $exp = 1 } else { $exp = 0 }
        ValidateSession
    }

    Process {
        try {
            $Requests = Get-PASRequest -RequestType $RequestType -OnlyWaiting $owa -Expired $exp -ErrorAction Stop | 
            Select-Object RequestID, Operation, RequestorUserName,
            @{ Name = 'CreationDate'  ; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.CreationDate))   } },
            @{ Name = 'ExpirationDate'; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.ExpirationDate)) } },
            @{ Name = 'AccessFrom'    ; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.AccessFrom))     } },
            @{ Name = 'AccessTo'      ; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.AccessTo))       } },
            AccessType, ConfirmationsLeft, RequestorReason | 
            Out-GridView -Title "Requests" -PassThru
            $Requests | Format-Table -AutoSize -Wrap
            $RequestID = $Requests.requestid

            foreach ($ID in $RequestID) {
                Deny-PASRequest -RequestID $ID -Reason $Reason -ErrorAction Stop
            }
        }
        catch {
            psserrorhandling
        }
    }

    End {}
}

# Approving request(s) in CyberArk
Function PSS-ApproveRequest {

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [string]
        $Reason
    )

    Begin {
        ValidateSession
    }

    Process {
        try {
            $Requests = Get-PASRequest -RequestType IncomingRequests -OnlyWaiting 1 -Expired 0 -ErrorAction Stop |
            Select-Object RequestID, Operation, RequestorUserName,
            @{ Name = 'CreationDate'  ; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.CreationDate))   } },
            @{ Name = 'ExpirationDate'; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.ExpirationDate)) } },
            @{ Name = 'AccessFrom'    ; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.AccessFrom))     } },
            @{ Name = 'AccessTo'      ; Expression = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.AccessTo))       } },
            AccessType, ConfirmationsLeft, RequestorReason | 
            Out-GridView -Title "Requests" -PassThru

            $Requests | Format-Table -AutoSize -Wrap
            $RequestID = $Requests.requestid

            foreach ($ID in $RequestID) { 
                Approve-PASRequest -RequestId $ID -Reason $Reason -ErrorAction Stop
            }
        }
        catch {
            psserrorhandling
        }
    }

    End {}
}

# Creates new request(s) in CyberArk
Function PSS-NewRequest {

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $PssHostName = $PSSServerEnv | Where-Object -FilterScript { $_ -match $wordToComplete }
                return $PssHostName
            } )]
        [string[]]
        $ComputerName,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $PssUserName = $PssUserNames | Where-Object -FilterScript { $_ -match $wordToComplete }
                return $PssUserName
            } )]
        [string]
        $Username,

        [parameter(Mandatory = $false)]
        [switch]
        $HostList,

        [parameter(Mandatory = $false)]
        [string]
        $HostFile,

        [Parameter(Mandatory = $false)]
        [switch]
        $MultipleAccessRequired,
        
        [Parameter(Mandatory = $false)]
        [switch]
        $AllowMappingLocalDrives,

        [Parameter(Mandatory = $false)]
        [switch]
        $FromDate,

        [Parameter(Mandatory = $false)]
        [switch]
        $Todate,

        [Parameter(Mandatory = $false)]
        [string]
        $Reason
    )

    Begin {
        ValidateSession
        $Global:ComputerName = $ComputerName
        if ($MultipleAccessRequired ) { $MAR  = 1     } else { $MAR  = 0    }
        if ($AllowMappingLocalDrives) { $AMLD = 'Yes' } else { $AMLD = 'No' }
        if ($HostList) {
            hostlistbox
        }
        if ($HostFile) {
            $res = Test-Path $HostFile
            if ($res = $true) {
                $Global:ComputerName = (Get-Content $HostFile)
            } else {Write-warning "Could not find the path or file."}
            
        }
        if ($ComputerName -eq $null) { Write-host -f Red "Computer name not provided."; Get-Command $MyInvocation.MyCommand -Syntax; break   }
        if ($FromDate              ) { FromDateSelector } else { [datetime]$Global:FromDateTime = get-date                                   }
        if ($ToDate                ) { ToDateSelector   } else { [datetime]$Global:ToDateTime   = (Get-Date $Global:FromDateTime).AddDays(1) }
        if ($res = Get-PASAccount | where { $_.remoteMachinesAccess -imatch "$ComputerName"}) {
            $PASAccounts = $res
            $RemoteMachine = "$ComputerName"
            $ComputerName = $PASAccounts.username
        }

        Function main_newpssrequest {
            $AccountID = $PASAccount.id
            $Plattform = $PASAccounts.platformId
            if ($Plattform -imatch 'WIN'                                ) { $CM = 'RDP'   ; $CC = 'PSM-RDP'         }
            if ($Plattform -imatch 'VMWARE'                             ) { $CM = 'PSMGW' ; $CC = 'PSM-VSPHERE-Web' }
            if ($Plattform -imatch 'LINUX' -or $Plattform -imatch 'UNIX') { $CM = 'PSMGW' ; $CC = 'PSM-SSH-BF'      }
            if ($Plattform -imatch 'LenovoLXCC'                         ) { $CM = 'PSMGW' ; $CC = 'PSM-LenovoLXCC'  }
            
            if ($RemoteMachine) {
                try {
                    New-PASRequest -AccountId $AccountID -Reason $Reason -MultipleAccessRequired $MAR -AllowMappingLocalDrives $AMLD -PSMRemoteMachine $RemoteMachine -FromDate "$FromDateTime" -ToDate "$ToDateTime" -ConnectionComponent $CC -ErrorAction Stop
                }
                catch {
                    psserrorhandling
                }
            }
            else {
                try {
                    New-PASRequest -AccountId $AccountID -Reason $Reason -MultipleAccessRequired $MAR -AllowMappingLocalDrives $AMLD -FromDate "$Global:FromDateTime" -ToDate "$Global:ToDateTime" -ConnectionComponent $CC -ErrorAction Stop
                }
                catch {
                    psserrorhandling
                }
            }
        }
    }

    Process {
        foreach ($Global:C in $ComputerName) {
            $PASAccounts = Get-PASAccount -search $C
            if (!$PASAccounts) {
                $PASAccounts = Get-PASAccount | where { $_.remoteMachinesAccess -imatch "$C" }
            }

            if (!$Username) {
                $Selection = $PASAccounts | Select-Object address, username, name | Out-GridView -Title "Accounts" -PassThru
                foreach ($Account in $Selection) {
                    $PASAccount = $PASAccounts | Where-Object { $_.address -imatch $Account.address -and $_.username -imatch $Account.userName }
                    main_newpssrequest
                }
            }
            else {
                $PASAccount = $PASAccounts | Where-Object { $_.address -imatch $Account.address -and $_.username -imatch $Username }
                main_newpssrequest
            }
        }
    }

    End {}
}

# Checking if an account has dual control enabled (4-eyes)
Function PSS-DualControlCheck {

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $PssHostName = $PSSServerEnv | Where-Object -FilterScript { $_ -match $wordToComplete }
                return $PssHostName
            } )]
        [string[]]
        $Global:ComputerName,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $PssUserName = $PssUserNames | Where-Object -FilterScript { $_ -match $wordToComplete }
                return $PssUserName
            } )]
        [string]
        $Username,

        [parameter(Mandatory = $false)]
        [ValidateSet('Linux', 'Windows')]
        [string]
        $Platform,

        [parameter(Mandatory = $false)]
        [switch]$HostList,

        [parameter(Mandatory = $false)]
        [string]
        $HostFile,

        [parameter(Mandatory = $false)]
        [ValidateSet('RequestNeeded', 'RequestNotNeeded')]
        [string]
        $ShowApproval

    )

    Begin {
        if ($HostList) {
            hostlistbox
        }

        if ($HostFile) {
            $res = Test-Path $HostFile
            if ($res = $true) {
                $Global:ComputerName = (Get-Content $HostFile)
            }
            else {
                Write-warning "Could not find the path or file."
            }
        }

        if ($ComputerName -eq $null) { Write-host -f Red "Computer name not provided."; Get-Command $MyInvocation.MyCommand -Syntax; break }
        ValidateSession
    }
    
    Process {
        foreach ($C in $ComputerName) {
            if ($Username) {
                if ($Platform) {
                    $ID = Get-PASAccount -search $C | Where-Object { $_.userName -imatch $Username -and $_.name -imatch $Platform } | Select-Object -ExpandProperty id
                    if (!$ID) {
                        $ID = Get-PASAccount | Where-Object { $_.remoteMachinesAccess -imatch $C -and $_.userName -imatch $Username -and $_.name -imatch $Platform } | Select-Object -ExpandProperty id
                        if (!$ID) {
                            Write-Host -ForegroundColor Red "No match."
                            break
                        }
                    }
                }
                else {
                    $ID = Get-PASAccount -search $C | Where-Object { $_.userName -imatch $Username } | Select-Object -ExpandProperty id
                    if (!$ID) {
                        $ID = Get-PASAccount | Where-Object { $_.remoteMachinesAccess -imatch $C -and $_.userName -imatch $Username } | Select-Object -ExpandProperty id
                        if (!$ID) {
                            Write-Host -ForegroundColor Red "No match."
                            break
                        }
                    }
                }
            }
            else {
                if ($Platform) {
                    $ID = Get-PASAccount -search $C | Where-Object { $_.name -imatch $Platform } | Select-Object -ExpandProperty id
                    if (!$ID) {
                        $ID = Get-PASAccount | Where-Object { $_.remoteMachinesAccess -imatch $C -and $_.name -imatch $Platform } | Select-Object -ExpandProperty id
                        if (!$ID) {
                            Write-Host -ForegroundColor Red "No match."
                            break
                        }
                    }
                }
                else {
                    $ID = Get-PASAccount -search $C | Select-Object -ExpandProperty id
                    if (!$ID) {
                        $ID = Get-PASAccount | Where-Object { $_.remoteMachinesAccess -imatch $C } | Select-Object -ExpandProperty id
                        if (!$ID) {
                            Write-Host -ForegroundColor Red "No match."
                            break
                        }
                    }
                }
            }

            if ($ID -eq $null) {
                Write-Host -f Red -b Black "No match found."
            }
            else {
                $ID | ForEach-Object {
                    $AccountDetails = Get-PASAccountDetail -id $_
                    if ($ShowApproval) {
                        $AccountDetails.details.name + ' -- ' + $AccountDetails.details.DualControlStatus | Select-String $ShowApproval
                    }
                    else {
                        $AccountDetails.details.name + ' -- ' + $AccountDetails.details.DualControlStatus
                    }
                }
            }
        }
    }

    End {}
}

# Calendar GUI to select date and time. Used in function PSS-NewRequest to set the FromDate variable
Function FromDateSelector {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Form
    $form                 = New-Object System.Windows.Forms.Form -Property @{
        Text              = "Select From Date and Time. "
        Size              = New-Object System.Drawing.Size(460, 325)
        StartPosition     = [System.Windows.Forms.FormStartPosition]:: CenterScreen
        KeyPreview        = $True
    }

    # the "OK" button 
    $OKButton             = New-Object System.Windows.Forms.Button -Property @{
        Location          = New-Object System.Drawing.Size(70, 240)
        Size              = New-Object System.Drawing.Size(75, 25)
        Text              = 'OK'
        DialogResult      = [System.Windows.Forms.DialogResult]::OK
    }

    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    # the "Cancel" button
    $CancelButton         = New-Object System.Windows.Forms.Button -Property @{
        Location          = New-Object System.Drawing.Size(170, 240)
        Size              = New-Object System.Drawing.Size(75, 25)
        Text              = 'Cancel'
        DialogResult      = [System.Windows.Forms.DialogResult]::Cancel
    }

    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    # Label
    $objLabel             = New-Object System.Windows.Forms.Label
    $objLabel.Location    = New-Object System.Drawing.Size(300, 150)
    $objLabel.Size        = New-Object System.Drawing.Size(150, 50)

    #Handler - saving user input
    $Handler_objCalendar_DateSelected = {        
        $objLabel.Text                = "Selected Date: $($objCalendar.SelectionStart.ToShortDateString())"
        $Global:SelectedDate          = $($objCalendar.SelectionStart.ToShortDateString())
    }

    # Calendar
    $objCalendar          = New-Object Windows.Forms.MonthCalendar -Property @{
        ShowTodayCircle   = $True
        MaxSelectionCount = 1
        Size              = New-Object System.Drawing.Size(200, 200)
        Location          = New-Object System.Drawing.Size(20, 20)
     
    }

    $objCalendar.add_DateSelected($Handler_objCalendar_DateSelected)

    $form.Controls.Add($objCalendar)
    $form.Controls.Add($objLabel)

    # Hour drop down list
    $objHourList          = New-Object System.Windows.Forms.ListBox
    $objHourList.Location = New-Object System.Drawing.Size(300, 20)
    $objHourList.Size     = New-Object System.Drawing.Size(50, 125)

    for ($i = 1; $i -le 24; $i++) {
        $objHourList.Items.Add("${i}:00") | Out-Null
    }

    $form.Controls.Add($objHourList)

    $result = $form.ShowDialog()

    if ($result -eq [Windows.Forms.DialogResult]::OK) {
        $FromDateTimeRes     = "$SelectedDate $($objHourList.SelectedItem) $($objAMPM.Text)"
        $Global:FromDateTime = get-date $FromDateTimeRes
    }
}

# Calendar GUI to select date and time. Used in function PSS-NewRequest  to set the ToDate variable
Function ToDateSelector {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Form
    $form                 = New-Object System.Windows.Forms.Form -Property @{
        Text              = "Select To Date and Time. "
        Size              = New-Object System.Drawing.Size(460, 325)
        StartPosition     = [System.Windows.Forms.FormStartPosition]:: CenterScreen
        KeyPreview        = $True
    }

    # the "OK" button 
    $OKButton             = New-Object System.Windows.Forms.Button -Property @{
        Location          = New-Object System.Drawing.Size(70, 240)
        Size              = New-Object System.Drawing.Size(75, 25)
        Text              = 'OK'
        DialogResult      = [System.Windows.Forms.DialogResult]::OK
    }

    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    # the "Cancel" button
    $CancelButton         = New-Object System.Windows.Forms.Button -Property @{
        Location          = New-Object System.Drawing.Size(170, 240)
        Size              = New-Object System.Drawing.Size(75, 25)
        Text              = 'Cancel'
        DialogResult      = [System.Windows.Forms.DialogResult]::Cancel
    }

    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    # Label
    $objLabel             = New-Object System.Windows.Forms.Label
    $objLabel.Location    = New-Object System.Drawing.Size(300, 150)
    $objLabel.Size        = New-Object System.Drawing.Size(150, 50)

    #Handler - saving user input
    $Handler_objCalendar_DateSelected = {        
        $objLabel.Text                = "Selected Date: $($objCalendar.SelectionStart.ToShortDateString())"
        $Global:SelectedDate          = $($objCalendar.SelectionStart.ToShortDateString())
    }

    # Calendar
    $objCalendar          = New-Object Windows.Forms.MonthCalendar -Property @{
        ShowTodayCircle   = $True
        MaxSelectionCount = 1
        Size              = New-Object System.Drawing.Size(200, 200)
        Location          = New-Object System.Drawing.Size(20, 20)
     
    }

    $objCalendar.add_DateSelected($Handler_objCalendar_DateSelected)

    $form.Controls.Add($objCalendar)
    $form.Controls.Add($objLabel)

    # Hour drop down list
    $objHourList          = New-Object System.Windows.Forms.ListBox
    $objHourList.Location = New-Object System.Drawing.Size(300, 20)
    $objHourList.Size     = New-Object System.Drawing.Size(50, 125)

    for ($i = 1; $i -le 24; $i++) {
        $objHourList.Items.Add("${i}:00") | Out-Null
    }

    $form.Controls.Add($objHourList)

    $result = $form.ShowDialog()

    if ($result -eq [Windows.Forms.DialogResult]::OK) {
        $ToDateTimeRes     = "$SelectedDate $($objHourList.SelectedItem) $($objAMPM.Text)"
        $Global:ToDateTime = get-date $ToDateTimeRes
    }
}

# GUI text box for hostlist
Function hostlistbox () {
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms

    # Create the Label.
    $label                 = New-Object System.Windows.Forms.Label
    $label.Location        = New-Object System.Drawing.Size(10,10)
    $label.Size            = New-Object System.Drawing.Size(280,20)
    $label.AutoSize        = $true
    $label.Text            = $Message

    # Create the TextBox used to capture the user's text.
    $textBox               = New-Object System.Windows.Forms.TextBox
    $textBox.Location      = New-Object System.Drawing.Size(10,40)
    $textBox.Size          = New-Object System.Drawing.Size(575,200)
    $textBox.AcceptsReturn = $true
    $textBox.AcceptsTab    = $false
    $textBox.Multiline     = $true
    $textBox.ScrollBars    = 'Both'
    $textBox.Text          = $DefaultText

    # Create the OK button.
    $okButton              = New-Object System.Windows.Forms.Button
    $okButton.Location     = New-Object System.Drawing.Size(415,250)
    $okButton.Size         = New-Object System.Drawing.Size(75,25)
    $okButton.Text         = "OK"
    $okButton.Add_Click({
        $lines    = $textBox.Lines  # Get the lines entered by the user.
        $form.Tag = $lines  # Save the array of lines to the Tag property.
        $form.Close()
    })

    # Create the Cancel button.
    $cancelButton          = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Size(510,250)
    $cancelButton.Size     = New-Object System.Drawing.Size(75,25)
    $cancelButton.Text     = "Cancel"
    $cancelButton.Add_Click({ $form.Tag = $null; $form.Close() })

    # Create the form.
    $form                  = New-Object System.Windows.Forms.Form
    $form.Text             = "Hostlist"
    $form.Size             = New-Object System.Drawing.Size(610,320)
    $form.FormBorderStyle  = 'FixedSingle'
    $form.StartPosition    = "CenterScreen"
    $form.AutoSizeMode     = 'GrowAndShrink'
    $form.Topmost          = $True
    $form.AcceptButton     = $okButton
    $form.CancelButton     = $cancelButton
    $form.ShowInTaskbar    = $true

    # Add all of the controls to the form.
    $form.Controls.Add($label)
    $form.Controls.Add($textBox)
    $form.Controls.Add($okButton)
    $form.Controls.Add($cancelButton)

    # Initialize and show the form.
    $form.Add_Shown({$form.Activate()})
    $result = $form.ShowDialog()

    # Return the array of lines that the user entered.
    $Global:ComputerName = $form.Tag
}

# Search through a list of all hosts in Cyberark
Function PSS-Host {
    param
    (
        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $PssHostName = $PSSServerEnv | Where-Object -FilterScript { $_ -match $wordToComplete }
                return $PssHostName
            } )]
        [string[]]
        $ComputerName,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $ID = $PlatformIDs | Where-Object -FilterScript { $_ -imatch $wordToComplete }
                return $ID
            } )]
        [string]
        $PlatformID
    )
  
    Begin {
        ValidateSession
    }

    Process {
        $Global:ComputerName = $ComputerName
        if ($PlatformID) {
            foreach ($C in $ComputerName) {
                $result = Get-PASAccount -search $C | where { $_.PlatformID -imatch $PlatformID } | Select-Object -ExpandProperty address | Sort-Object -Unique
                if (!$result) {
                    $result = Get-PASAccount | where { $_.PlatformID -imatch $PlatformID -and $_.remoteMachinesAccess -imatch $C } | select -ExpandProperty remoteMachinesAccess | Select -ExpandProperty remotemachines
                    if (!$result) { Write-Host -ForegroundColor Red "No match.";break}
                    Write-Host -ForegroundColor Yellow -BackgroundColor Black "Match found for remote machines."
                    return $result.Split(";")
                }
                else {
                    return $result
                }
            }
        } else {
            foreach ($C in $ComputerName) {
                $result = Get-PASAccount -search $C | Select-Object -ExpandProperty address | Sort-Object -Unique
                if (!$result) {
                    $result = Get-PASAccount | where { $_.remoteMachinesAccess -imatch $C } | select -ExpandProperty remoteMachinesAccess | Select -ExpandProperty remotemachines
                    if (!$result) { Write-Host -ForegroundColor Red "No match.";break}
                    Write-Host -ForegroundColor Yellow -BackgroundColor Black "Match found for remote machines."
                    return $result.Split(";")
                }
                else {
                    return $result
                }
            }
        }
    }

    End {}
}

Function PSS-Accounts {
    Begin {
        ValidateSession
    }

    Process {
        (Get-PASAccount).username | sort -Unique   
    }

    End {}
}

Function PSS-RemoteMachine {
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $ComputerName
    )

    begin {
        ValidateSession
    }

    Process {
        foreach ($Computer in $ComputerName) {
            Get-PASAccount | where { $_.remoteMachinesAccess -imatch "$Computer"} | Select-Object safename,address,username,name,platformid | ft -AutoSize -Wrap
            }
    }

    End {}
}

Function PSS-AddSafe {

    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $SafeName
    )

    Begin {
        ValidateSession
    }

    Process {
        $safeName | foreach {
            Add-PASSafe -SafeName $_ -NumberOfVersionsRetention 7

            $Role = [PSCustomObject]@{
                useAccounts=$true
                retrieveAccounts=$true
                listAccounts=$true
                addAccounts=$true
                updateAccountContent=$true
                updateAccountProperties=$true
                initiateCPMAccountManagementOperations=$true
                specifyNextAccountContent=$true
                renameAccounts=$true
                deleteAccounts=$true
                unlockAccounts=$true
                manageSafe=$true
                manageSafeMembers=$true
                backupSafe=$true
                viewAuditLog=$true
                viewSafeMembers=$true
                accessWithoutConfirmation=$true
                createFolders=$true
                deleteFolders=$true
                moveAccountsAndFolders=$true
                requestsAuthorizationLevel1=$true
                requestsAuthorizationLevel2=$false
            }

            $Role| Add-PASSafeMember -SafeName $_ -MemberName administrator -SearchIn Vault -ListAccounts $true
        }
    }

    End {
        write-host "Safe(s) $_ is created and administrator added."
    }
}

Function PSS-GetMemberSafes {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $MemberName
    )

    begin {
        ValidateSession
    }

    Process {
        Get-PASSafe | Get-PASSafeMember -ErrorAction SilentlyContinue | where {$_.username -imatch "$MemberName"} | select username,safename | Format-Table -AutoSize
    }

    End {}
}

Function PSS-UnlockUser {
    $res = foreach ($user in $((Get-PASUser).username)) { Get-PASUser -UserName $user -UseGen1API -ErrorAction SilentlyContinue | where {$_.suspended} }
    if ($null -ne $res) {
        $selectedUsers = $res | Out-GridView -Title "Suspended Accounts" -PassThru
        $selectedUsers.userName | foreach {Unblock-PASUser -UserName $_ -Suspended $false}
    }
    else {
        Write-Host "No suspended accounts found."
    }
}

Function PSS-GetSafeMembers {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $SafeName
    )

    begin {
        ValidateSession
    }
    
    Process {
        Get-PASSafe -Search "$SafeName" | foreach {
            Write-Host -ForegroundColor Green "Safe : " -NoNewline
            Write-Host -f Yellow $_.safename
            '-------------------------'
            ($_ | Get-PASSafeMember).username
            write-host ""
            }
    }
    
    End {}
}

Function PSS-GetGroupMembers {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $GroupName
    )

    begin {
        ValidateSession
    }
    
    Process {
        try {
            Get-PASGroup -search $GroupName -includeMembers $true | foreach {
                $groupname = $_.groupname
                $users     = $_.members | select -ExpandProperty username
                ""
                Write-Host -f green "Groupname: " -NoNewline
                write-host -f yellow $_.groupname
                write-host -f white '-------------------------'
                $users
                }
        }
        catch {
            psserrorhandling
        }
    }
    
    End {}
}

Function PSS-GetGroups {
    param
    (
        [Parameter(Mandatory = $false)]
        [string]
        $GroupName
    )

    begin {
        ValidateSession
    }
    
    Process {
        try {
            if ($null -eq $groupname) {
                Get-PASGroup
            }
            else {
                Get-PASGroup -search $GroupName | select groupname
            }
        }
        catch {
            psserrorhandling
        }
    }
    
    End {}
}

<#
Function template {
    param
    (
        [Parameter(Mandatory = $true/$false)]
        [string]
        $parametername
    )

    begin {
        ValidateSession
    }
    
    Process {
        try {
            code
        } 
        catch {
            psserrorhandling
        }
    }
    
    End {}
}
#>
