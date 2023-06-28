# Fixed values
$AutoMapping = $false

try {
    # Set TLS to accept TLS, TLS 1.1 and TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

    # Connect to Office 365
    try{
        Write-Information -Message "Connecting to Office 365.."

        $module = Import-Module ExchangeOnlineManagement

        $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername,$securePassword)

        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop 

        Write-Information -Message "Successfully connected to Office 365"

        $Log = @{
            Action            = "MailboxPermissions" # optional. ENUM (undefined = default) 
            System            = "ExchangeOnline" # optional (free format text) 
            Message           = "Successfully connected to Office 365" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = "" # optional (free format text) 
            TargetIdentifier  = "" # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log

    }catch{
        Write-Error "Could not connect to Exchange Online, error: $_"
    }

    Write-Information -Message "Checking if mailbox with identity '$($identity)' exists"
    $mailbox = Get-Mailbox -Identity $identity -ErrorAction Stop
    if ($mailbox.Name.Count -eq 0) {
        throw "Could not find mailbox with identity '$($identity)'"
    }

    # Add permissions to users
    try { 
        Write-Information -Message "Adding permission $($permission) to mailbox $($identity) for $usersToAdd" 
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
            Write-Information -Message "Added permission $($permission) to mailbox $($identity) for $User."

            $Log = @{
                Action            = "MailboxPermissions" # optional. ENUM (undefined = default) 
                System            = "ExchangeOnline" # optional (free format text) 
                Message           = "Added permission $($permission) to mailbox $($identity) for $User." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $User # optional (free format text) 
                TargetIdentifier  = $identity # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
    } catch {
        Write-Error -Message "Error adding permission $($permission) to mailbox $($identity) for $User. Error: $_"
        
        $Log = @{
            Action            = "MailboxPermissions" # optional. ENUM (undefined = default) 
            System            = "ExchangeOnline" # optional (free format text) 
            Message           = "Error adding permission $($permission) to mailbox $($identity) for $User." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $User # optional (free format text) 
            TargetIdentifier  = $identity # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }

    # Remove permissions from users
    try { 
        Write-Information -Message "Removing permission $($permission) to mailbox $($identity) for $usersToRemove" 
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
            Write-Information -Message "Removed permission $($permission) to mailbox $($identity) for $User."
            
            $Log = @{
                Action            = "MailboxPermissions" # optional. ENUM (undefined = default) 
                System            = "ExchangeOnline" # optional (free format text) 
                Message           = "Removed permission $($permission) to mailbox $($identity) for $User." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $User # optional (free format text) 
                TargetIdentifier  = $identity # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log         
        }
    } catch {
        Write-Error -Message "Error removing permission $($permission) to mailbox $($identity) for $User. Error: $_"

        $Log = @{
            Action            = "MailboxPermissions" # optional. ENUM (undefined = default) 
            System            = "ExchangeOnline" # optional (free format text) 
            Message           = "Error removing permission $($permission) to mailbox $($identity) for $User." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $User # optional (free format text) 
            TargetIdentifier  = $identity # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
} catch {
    Write-Error -Message "Error updating permission $($permission) to mailbox $($identity). Error: $_"
    
    $Log = @{
        Action            = "MailboxPermissions" # optional. ENUM (undefined = default) 
        System            = "ExchangeOnline" # optional (free format text) 
        Message           = "Error updating permission $($permission) to mailbox $($identity)." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = "" # optional (free format text) 
        TargetIdentifier  = $identity # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
} finally {
    Write-Information -Message "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    
    $Log = @{
        Action            = "MailboxPermissions" # optional. ENUM (undefined = default) 
        System            = "ExchangeOnline" # optional (free format text) 
        Message           = "Successfully Disconnecting from Office 365" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = "" # optional (free format text) 
        TargetIdentifier  = "" # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
