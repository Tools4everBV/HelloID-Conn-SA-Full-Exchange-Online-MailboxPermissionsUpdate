# PowerShell commands to import
$commands = @(
    "Get-user"
)

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }

        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            # $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message # Does not show the correct error message for the Raet IAM API calls
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [HelloID.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}
#endregion functions

#region Import module
try {           
    $moduleName = "ExchangeOnlineManagement"

    # If module is imported say that and do nothing
    if (Get-Module -Verbose:$false | Where-Object { $_.Name -eq $ModuleName }) {
        Write-Verbose "Module [$ModuleName] is already imported."
    }
    else {
        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable -Verbose:$false | Where-Object { $_.Name -eq $ModuleName }) {
            $module = Import-Module $ModuleName -Cmdlet $commands -Verbose:$false
            Write-Verbose "Imported module [$ModuleName]"
        }
        else {
            # If the module is not imported, not available and not in the online gallery then abort
            throw "Module [$ModuleName] is not available. Please install the module using: Install-Module -Name [$ModuleName] -Force"
        }
    }
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

    # Skip further actions, as this is a critical error
    throw "Error importing module [$ModuleName]. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Import module

#region Connect to Exchange
try {
    # Create credentials object
    Write-Verbose "Creating Credentials object"
    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername, $securePassword)

    # Connect to Exchange Online in an unattended scripting scenario using an access token.
    Write-Verbose "Connecting to Exchange Online"

    $exchangeSessionParams = @{
        Credential       = $credential
        CommandName      = $commands
        ShowBanner       = $false
        ShowProgress     = $false
        TrackPerformance = $false
        ErrorAction      = "Stop"
    }
    $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams
    
    Write-Information "Successfully connected to Exchange Online"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

    # Skip further actions, as this is a critical error
    throw "Error connecting to Exchange Online. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Connect to Exchange

#region Get Users
try {
    $properties = @(
        "Id"
        , "Guid"
        , "Name"
        , "DisplayName"
        , "UserPrincipalName"
    )

    $exchangeQuerySplatParams = @{
        Filter     = "*"
        ResultSize = "Unlimited"
    }
    if (-not[String]::IsNullOrEmpty($filter)) {
        $exchangeQuerySplatParams.Add("Filter", $filter)
    }

    Write-Information "Querying users that match filter [$($exchangeQuerySplatParams.Filter)]"
    $users = Get-User @exchangeQuerySplatParams | Select-Object $properties

    $users = $users | Sort-Object -Property Name
    $resultCount = ($users | Measure-Object).Count
    Write-Information "Result count: $resultCount"

    # # Filter out users without name
    # Write-Information "Filtering out users without [name]"
    # $users = $users | Where-Object { -NOT[String]::IsNullOrEmpty($_.name) }
    # $resultCount = ($users | Measure-Object).Count
    # Write-Information "Result count: $resultCount"
    
    if ($resultCount -gt 0) {
        foreach ($user in $users) {
            $displayValue = $user.displayName + " [" + $user.userPrincipalName + "]"
            $returnObject = @{
                displayValue      = $displayValue;
                userPrincipalName = "$($user.userPrincipalName)";
                id                = "$($user.id)";
                guid              = "$($user.guid)";
            }
     
            Write-Output $returnObject
        }
    }
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying users that match filter [$($exchangeQuerySplatParams.Filter)]. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get Users
