# Fixed values
$AutoMapping = $false

try {
    # Set TLS to accept TLS, TLS 1.1 and TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

    # Connect to Office 365
    try{
        Hid-Write-Status -Event Information -Message "Connecting to Office 365.."

        $module = Import-Module ExchangeOnlineManagement

        $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($ExchangeOnlineAdminUsername, $securePassword)

        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop 

        Hid-Write-Status -Event Information -Message "Successfully connected to Office 365"
    }catch{
        Write-Error "Could not connect to Exchange Online, error: $_"
    }

    Hid-Write-Status -Event Information -Message "Checking if mailbox with identity '$($identity)' exists"
    $mailbox = Get-Mailbox -Identity $identity -ErrorAction Stop
    if ($mailbox.Name.Count -eq 0) {
        throw "Could not find mailbox with identity '$($identity)'"
    }

    # Add permissions to users
    try { 
        HID-Write-Status -Event Information -Message "Adding permission $($permission) to mailbox $($identity) for $usersToAdd" 
        $usersToAddJson = $usersToAdd | ConvertFrom-Json
        foreach ($user in $usersToAddJson.id) {
            if($permission.ToLower() -eq "fullaccess"){
                if($AutoMapping){
                    Add-MailboxPermission -Identity $mailbox.DistinguishedName -AccessRights FullAccess -InheritanceType All -AutoMapping:$true -User $User -ErrorAction Stop
                }else{
                    Add-MailboxPermission -Identity $mailbox.DistinguishedName -AccessRights FullAccess -InheritanceType All -AutoMapping:$false -User $User -ErrorAction Stop
                }
            }elseif($permission.ToLower() -eq "sendas"){
                Add-RecipientPermission -Identity $mailbox.DistinguishedName -AccessRights SendAs -Confirm:$false -Trustee $User -ErrorAction Stop
            }elseif($permission.ToLower() -eq "sendonbehalf"){
                Set-Mailbox -Identity $mailbox.DistinguishedName -GrantSendOnBehalfTo @{add="$user"} -Confirm:$false -ErrorAction Stop
            }else{
                throw "Could not match right '$($permission)' to FullAccess, SendAs or SendOnBehalf"
            }
            HID-Write-Status -Event Success -Message "Added permission $($permission) to mailbox $($identity) for $User."
            HID-Write-Summary -Event Success -Message "Added permission $($permission) to mailbox $($identity) for $User."
        }
    } catch {
        HID-Write-Status -Event Error -Message "Error adding permission $($permission) to mailbox $($identity) for $User. Error: $_"
        HID-Write-Summary -Event Failed -Message "Error adding permission $($permission) to mailbox $($identity) for $User."
    }

    # Remove permissions from users
    try { 
        HID-Write-Status -Event Information -Message "Removing permission $($permission) to mailbox $($identity) for $usersToRemove" 
        $usersToRemoveJson = $usersToRemove | ConvertFrom-Json
        foreach ($user in $usersToRemoveJson.id) {
            if($permission.ToLower() -eq "fullaccess"){
                Remove-MailboxPermission -Identity $mailbox.DistinguishedName -AccessRights FullAccess -InheritanceType All -User $User -Confirm:$false -ErrorAction Stop
            }elseif($permission.ToLower() -eq "sendas"){
                Remove-RecipientPermission -Identity $mailbox.DistinguishedName -AccessRights SendAs -Confirm:$false -Trustee $User -ErrorAction Stop
            }elseif($permission.ToLower() -eq "sendonbehalf"){
                Set-Mailbox -Identity $mailbox.DistinguishedName -GrantSendOnBehalfTo @{remove="$user"} -Confirm:$false -ErrorAction Stop
            }else{
                throw "Could not match right '$($permission)' to FullAccess, SendAs or SendOnBehalf"
            }
            HID-Write-Status -Event Success -Message "Removed permission $($permission) to mailbox $($identity) for $User."
            HID-Write-Summary -Event Success -Message "Removed permission $($permission) to mailbox $($identity) for $User."          
        }
    } catch {
        HID-Write-Status -Event Error -Message "Error removing permission $($permission) to mailbox $($identity) for $User. Error: $_"
        HID-Write-Summary -Event Failed -Message "Error removing permission $($permission) to mailbox $($identity) for $User."
    }
} catch {
    HID-Write-Status -Message "Error updating permission $($permission) to mailbox $($identity). Error: $_" -Event Error
    HID-Write-Summary -Message "Error updating permission $($permission) to mailbox $($identity)." -Event Failed
} finally {
    Hid-Write-Status -Event Information -Message "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Hid-Write-Status -Event Information -Message "Successfully disconnected from Office 365"
}
