# CyberArk Powershell Tools

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


# Global variables
Global variables that needs to be set before use:

          $Global:ScriptTextFilesLocation = "<PATH>" # Set location where usernames, hostnames and platforms are stored.
          $Global:BaseURI                 = '<SERVERNAME>' # Set the pvwa server

Global variables that might need to be changed:

          $Global:domain                  = "$env:USERDNSDOMAIN" # Set the login domain for pvwa
          $Global:Type                    = "LDAP" # CyberArk login type. LDAP or cyberark.


If you have multiple pvwa servers in your environment like stage/test with different logon parameters or credentials, there is a script block to check for a specific hostname prefix under CyberArkSession function
              if ($ComputerName -imatch "pvwa-stage") {
                  $Global:BaseURI = "<SERVERNAME_FOR_TEST>"
              }
