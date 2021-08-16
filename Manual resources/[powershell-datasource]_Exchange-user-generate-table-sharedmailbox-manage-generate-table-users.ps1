# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Connect to Office 365
try{
     Write-Information "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($ExchangeOnlineAdminUsername, $securePassword)

    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop 

    Write-Information "Successfully connected to Office 365"
}catch{
    Write-Error "Could not connect to Exchange Online, error: $_"
}

try {
    $exchangeOnlineUsers = Get-User -Identity * -ResultSize Unlimited

    $users = $exchangeOnlineUsers
    $resultCount = @($users).Count
     
    Write-Information -Message "Result count: $resultCount"

    if($resultCount -gt 0){
        foreach($user in $users){
            $displayValue = $user.displayName + " [" + $user.UserPrincipalName + "]"
            $returnObject = @{
                name=$displayValue;
                UserPrincipalName="$($user.UserPrincipalName)";
                id="$($user.id)";
            }
     
            Write-Output $returnObject
        }
    }
} catch {
    Write-Error "Error searching users. Error: $_"
} finally {
    Write-Information "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Write-Information "Successfully disconnected from Office 365"
}
