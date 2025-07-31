# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("User Management","Exchange Online","mailbox Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> ExchangeOnlineAdminPassword
$tmpName = @'
ExchangeOnlineAdminPassword
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> ExchangeOnlineAdminUsername
$tmpName = @'
ExchangeOnlineAdminUsername
'@ 
$tmpValue = @'
exchangeadmin@enyoi.onmicrosoft.com
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"
# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}
# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}
# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  
# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}
function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )
    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid
            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}
function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task
            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid
            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }
    $returnObject.Value = $taskGuid
}
function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }
    $returnObject.Value = $datasourceGuid
}
function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }
    $returnObject.Value = $formGuid
}
function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true
            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }
    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}

<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "Exchange-user-generate-table-sharedmailbox-manage-generate-table-users" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"userPrincipalName","type":0},{"key":"displayValue","type":0},{"key":"guid","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Exchange-user-generate-table-sharedmailbox-manage-generate-table-users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Exchange-user-generate-table-sharedmailbox-manage-generate-table-users" #>

<# Begin: DataSource "Exchange-user-generate-table-sharedmailbox-manage-generate-table-users-permission" #>
$tmpPsScript = @'
$identity = $datasource.selectedmailbox.id
$Permission = $datasource.Permission

# PowerShell commands to import
$commands = @(
    "Get-Mailbox"
    , "Get-EXOMailbox"
    , "Get-RecipientPermission"
    , "Get-MailboxPermission"
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

# Get current mailbox permissions
try {
    if ($Permission.ToLower() -eq "fullaccess") {
        $currentPermissions = Get-MailboxPermission -Identity $identity # Returns UPN

        $currentPermissions = $currentPermissions | Where-Object { ($_.accessRights -like "*fullaccess*") -and -not($_.Deny -eq $true) -and -not($_.User -match "NT AUTHORITY") -and -not($_.User -like "*\Domain Admins") }
        $currentPermissionsUsers = $currentPermissions.User    
    }
    elseif ($Permission.ToLower() -eq "sendas") {
        $currentPermissions = Get-RecipientPermission -Identity $identity -AccessRights 'SendAs' # Returns UPN

        $currentPermissions = $currentPermissions | Where-Object { -not($_.Deny -eq $true) -and -not($_.Trustee -match "NT AUTHORITY") -and -not($_.Trustee -like "*\Domain Admins") }
        $currentPermissionsUsers = $currentPermissions.Trustee
    }
    elseif ($Permission.ToLower() -eq "sendonbehalf") {
        $exchangeMailbox = Get-EXOMailbox -Identity $identity -resultSize unlimited

        $currentPermissions = $exchangeMailbox | ForEach-Object { $_.GrantSendOnBehalfTo } # Returns name only
        $currentPermissionsUsers = $currentPermissions
    }
    else {
        throw "Could not match right '$($Permission)' to FullAccess, SendAs or SendOnBehalf"
    }

    $users = foreach ($currentPermissionsUser in $currentPermissionsUsers) {
        Get-User -Identity $currentPermissionsUser -ErrorAction SilentlyContinue
    }
    
    $users = $users | Sort-Object -Property Displayname
    Write-Information -Message "Found $Permission permissions to mailbox $($identity): $(@($users).Count)"

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
catch {
    Write-Error "Error searching $Permissions permissions to mailbox $($identity). Error: $_"
}
'@ 
$tmpModel = @'
[{"key":"displayValue","type":0},{"key":"userPrincipalName","type":0},{"key":"id","type":0},{"key":"guid","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedMailbox","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Permission","type":0,"options":1}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
Exchange-user-generate-table-sharedmailbox-manage-generate-table-users-permission
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "Exchange-user-generate-table-sharedmailbox-manage-generate-table-users-permission" #>

<# Begin: DataSource "exchange-online-shared-mailbox-manage-permissions-generate-table-mailbox-wildcard" #>
$tmpPsScript = @'
# Warning! When no searchQuery is specified. All mailboxes will be retrieved.
$searchValue = $datasource.searchValue

if ([String]::IsNullOrEmpty($searchValue) -or $searchValue -eq "*") {
    $filter = "*"
}
else {
    $filter = "Name -like '*$searchValue*' -or EmailAddresses -like '*$searchValue*'"
}

# PowerShell commands to import
$commands = @(
    "Get-Mailbox"
    , "Get-EXOMailbox"
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

#region Get Mailboxes
try {
    $properties = @(
        "Id"
        , "Guid"
        , "ExchangeGuid"
        , "Name"
        , "DisplayName"
        , "UserPrincipalName"
        , "EmailAddresses"
        , "RecipientTypeDetails"
        , "Alias"
    )

    $exchangeQuerySplatParams = @{
        RecipientTypeDetails = "SharedMailbox"
        ResultSize           = "Unlimited"
    }
    if (-not[String]::IsNullOrEmpty($filter)) {
        $exchangeQuerySplatParams.Add("Filter", $filter)
    }

    Write-Information "Querying shared mailboxes that match filter [$($exchangeQuerySplatParams.Filter)]"
    $mailboxes = Get-EXOMailbox @exchangeQuerySplatParams | Select-Object $properties

    $mailboxes = $mailboxes | Sort-Object -Property Name
    $resultCount = ($mailboxes | Measure-Object).Count
    Write-Information "Result count: $resultCount"

    # # Filter out mailboxes without name
    # Write-Information "Filtering out mailboxes without [name]"
    # $mailboxes = $mailboxes | Where-Object { -NOT[String]::IsNullOrEmpty($_.name) }
    # $resultCount = ($mailboxes | Measure-Object).Count
    # Write-Information "Result count: $resultCount"
    
    if ($resultCount -gt 0) {
        foreach ($mailbox in $mailboxes) {
            Write-Output $mailbox
        }
    }
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying shared mailboxes that match filter [$($exchangeQuerySplatParams.Filter)]. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get Mailboxes
'@ 
$tmpModel = @'
[{"key":"Id","type":0},{"key":"Guid","type":0},{"key":"Name","type":0},{"key":"DisplayName","type":0},{"key":"UserPrincipalName","type":0},{"key":"EmailAddresses","type":0},{"key":"RecipientTypeDetails","type":0},{"key":"Alias","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchValue","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
exchange-online-shared-mailbox-manage-permissions-generate-table-mailbox-wildcard
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "exchange-online-shared-mailbox-manage-permissions-generate-table-mailbox-wildcard" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Exchange online - Shared mailbox - Manage permissions" #>
$tmpSchema = @"
[{"label":"Details","fields":[{"templateOptions":{},"type":"markdown","summaryVisibility":"Show","body":"Retrieving this information from Exchange takes an average of +/- 10 seconds.  \nPlease wait while we load the data.","requiresTemplateOptions":false,"requiresKey":false,"requiresDataSource":false},{"key":"searchMailbox","templateOptions":{"label":"Search","placeholder":""},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridMailbox","templateOptions":{"label":"Mailbox","required":true,"grid":{"columns":[{"headerName":"Name","field":"Name"},{"headerName":"Display Name","field":"DisplayName"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Email Addresses","field":"EmailAddresses"},{"headerName":"Alias","field":"Alias"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchValue","otherFieldValue":{"otherFieldKey":"searchMailbox"}}]}},"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Mailbox Permissions","fields":[{"templateOptions":{},"type":"markdown","summaryVisibility":"Show","body":"Retrieving this information from Exchange takes an average of +/- 30 seconds.  \nPlease wait while we load the data.","requiresTemplateOptions":false,"requiresKey":false,"requiresDataSource":false},{"key":"permission","templateOptions":{"label":"Permission","required":false,"useObjects":true,"useDataSource":false,"useFilter":false,"options":[{"value":"fullaccess","text":"Full Access"},{"value":"sendas","text":"Send As"},{"value":"sendonbehalf","text":"Send on Behalf"}]},"type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"permissionList","templateOptions":{"label":"Full Access permissions","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"guid","optionDisplayProperty":"displayValue"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[]}},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"selectedMailbox","otherFieldValue":{"otherFieldKey":"gridMailbox"}},{"propertyName":"Permission","otherFieldValue":{"otherFieldKey":"permission"}}]}}},"hideExpression":"!model[\"permission\"]","type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Exchange online - Shared mailbox - Manage permissions
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}
$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $response = $response | Where-Object {$_.name.en -eq $category}
        
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Exchange online - Shared mailbox - Manage permissions
'@
$tmpTask = @'
{"name":"Exchange online - Shared mailbox - Manage permissions","script":"$identity = $form.gridMailbox.id\r\n$permission = $form.permission\r\n$usersToAdd = $form.permissionList.leftToRight\r\n$usersToRemove = $form.permissionList.rightToLeft\r\n\r\n# Fixed values\r\n$AutoMapping = $false\r\n\r\n# PowerShell commands to import\r\n$commands = @(\r\n    \"Get-Mailbox\"\r\n    , \"Get-EXOMailbox\"\r\n    , \"Set-Mailbox\"\r\n    , \"Add-MailboxPermission\"\r\n    , \"Add-RecipientPermission\"\r\n    , \"Remove-MailboxPermission\"\r\n    , \"Remove-RecipientPermission\"\r\n)\r\n\r\n# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n#region functions\r\nfunction Resolve-HTTPError {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory,\r\n            ValueFromPipeline\r\n        )]\r\n        [object]$ErrorObject\r\n    )\r\n    process {\r\n        $httpErrorObj = [PSCustomObject]@{\r\n            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId\r\n            MyCommand             = $ErrorObject.InvocationInfo.MyCommand\r\n            RequestUri            = $ErrorObject.TargetObject.RequestUri\r\n            ScriptStackTrace      = $ErrorObject.ScriptStackTrace\r\n            ErrorMessage          = \u0027\u0027\r\n        }\r\n\r\n        if ($ErrorObject.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) {\r\n            # $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message # Does not show the correct error message for the Raet IAM API calls\r\n            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message\r\n\r\n        }\r\n        elseif ($ErrorObject.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027) {\r\n            $httpErrorObj.ErrorMessage = [HelloID.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()\r\n        }\r\n\r\n        Write-Output $httpErrorObj\r\n    }\r\n}\r\n\r\nfunction Get-ErrorMessage {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory,\r\n            ValueFromPipeline\r\n        )]\r\n        [object]$ErrorObject\r\n    )\r\n    process {\r\n        $errorMessage = [PSCustomObject]@{\r\n            VerboseErrorMessage = $null\r\n            AuditErrorMessage   = $null\r\n        }\r\n\r\n        if ( $($ErrorObject.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or $($ErrorObject.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\r\n            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject\r\n\r\n            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage\r\n\r\n            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage\r\n        }\r\n\r\n        # If error message empty, fall back on $ex.Exception.Message\r\n        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {\r\n            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message\r\n        }\r\n        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {\r\n            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message\r\n        }\r\n\r\n        Write-Output $errorMessage\r\n    }\r\n}\r\n#endregion functions\r\n\r\n#region Import module\r\ntry {           \r\n    $moduleName = \"ExchangeOnlineManagement\"\r\n\r\n    # If module is imported say that and do nothing\r\n    if (Get-Module -Verbose:$false | Where-Object { $_.Name -eq $ModuleName }) {\r\n        Write-Verbose \"Module [$ModuleName] is already imported.\"\r\n    }\r\n    else {\r\n        # If module is not imported, but available on disk then import\r\n        if (Get-Module -ListAvailable -Verbose:$false | Where-Object { $_.Name -eq $ModuleName }) {\r\n            $module = Import-Module $ModuleName -Cmdlet $commands -Verbose:$false\r\n            Write-Verbose \"Imported module [$ModuleName]\"\r\n        }\r\n        else {\r\n            # If the module is not imported, not available and not in the online gallery then abort\r\n            throw \"Module [$ModuleName] is not available. Please install the module using: Install-Module -Name [$ModuleName] -Force\"\r\n        }\r\n    }\r\n}\r\ncatch {\r\n    $ex = $PSItem\r\n    $errorMessage = Get-ErrorMessage -ErrorObject $ex\r\n\r\n    Write-Verbose \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)\"\r\n\r\n    # Skip further actions, as this is a critical error\r\n    throw \"Error importing module [$ModuleName]. Error Message: $($errorMessage.AuditErrorMessage)\"\r\n}\r\n#endregion Import module\r\n\r\n#region Connect to Exchange\r\ntry {\r\n    # Create credentials object\r\n    Write-Verbose \"Creating Credentials object\"\r\n    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force\r\n    $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername, $securePassword)\r\n\r\n    # Connect to Exchange Online in an unattended scripting scenario using an access token.\r\n    Write-Verbose \"Connecting to Exchange Online\"\r\n\r\n    $exchangeSessionParams = @{\r\n        Credential       = $credential\r\n        CommandName      = $commands\r\n        ShowBanner       = $false\r\n        ShowProgress     = $false\r\n        TrackPerformance = $false\r\n        ErrorAction      = \"Stop\"\r\n    }\r\n    $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams\r\n    \r\n    Write-Information \"Successfully connected to Exchange Online\"\r\n}\r\ncatch {\r\n    $ex = $PSItem\r\n    $errorMessage = Get-ErrorMessage -ErrorObject $ex\r\n\r\n    Write-Verbose \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)\"\r\n\r\n    # Skip further actions, as this is a critical error\r\n    throw \"Error connecting to Exchange Online. Error Message: $($errorMessage.AuditErrorMessage)\"\r\n}\r\n#endregion Connect to Exchange\r\n\r\n#region Get Mailbox\r\ntry {\r\n    $properties = @(\r\n        \"Id\"\r\n        , \"Guid\"\r\n        , \"ExchangeGuid\"\r\n        , \"DistinguishedName\"\r\n        , \"Name\"\r\n        , \"DisplayName\"\r\n        , \"UserPrincipalName\"\r\n        , \"EmailAddresses\"\r\n        , \"RecipientTypeDetails\"\r\n        , \"Alias\"\r\n    )\r\n\r\n    $exchangeQuerySplatParams = @{\r\n        Identity   = $identity\r\n        ResultSize = \"Unlimited\"\r\n    }\r\n\r\n    Write-Information \"Querying mailbox with identity [$identity]\"\r\n    $mailbox = Get-EXOMailbox @exchangeQuerySplatParams | Select-Object $properties\r\n}\r\ncatch {\r\n    $ex = $PSItem\r\n    $errorMessage = Get-ErrorMessage -ErrorObject $ex\r\n\r\n    Write-Verbose \"Error at Line \u0027$($ex.InvocationInfo.ScriptLineNumber)\u0027: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))\"\r\n\r\n    throw \"Error querying mailbox with identity [$identity]. Error Message: $($errorMessage.AuditErrorMessage)\"\r\n}\r\n#endregion Get Mailbox\r\n\r\n#region Grant selected users permissions to shared mailbox\r\nforeach ($userToAdd in $usersToAdd) {\r\n    switch ($permission) {\r\n        \"fullaccess\" {\r\n            #region Grant Full Access to shared mailbox\r\n            try {\r\n                Write-Verbose \"Granting permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]\"\r\n\r\n                $FullAccessPermissionSplatParams = @{\r\n                    Identity        = $mailbox.Guid\r\n                    User            = $userToAdd.guid\r\n                    AccessRights    = \"FullAccess\"\r\n                    InheritanceType = \"All\"\r\n                    AutoMapping     = $automapping\r\n                    ErrorAction     = \"Stop\"\r\n                    WarningAction   = \"SilentlyContinue\"\r\n                } \r\n\r\n                $addFullAccessPermission = Add-MailboxPermission @FullAccessPermissionSplatParams\r\n\r\n                Write-Information \"Successfully granted permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text) \r\n                    Message           = \"Successfully granted permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]\" # required (free format text) \r\n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back\r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n            }\r\n            catch {\r\n                # Clean up error variables\r\n                $verboseErrorMessage = $null\r\n                $auditErrorMessage = $null\r\n\r\n                $ex = $PSItem\r\n                # If error message empty, fall back on $ex.Exception.Message\r\n                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n                    $verboseErrorMessage = $ex.Exception.Message\r\n                }\r\n                if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n                    $auditErrorMessage = $ex.Exception.Message\r\n                }\r\n\r\n                Write-Verbose \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text)\r\n                    Message           = \"Failed to grant permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]. Error Message: $auditErrorMessage\" # required (free format text) \r\n                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back\r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n                Write-Error \"Error granting permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]. Error Message: $auditErrorMessage\"\r\n            }\r\n            #endregion Grant Full Access to shared mailbox\r\n            break\r\n        }\r\n            \r\n        \"sendas\" {\r\n            #region Grant Send As to shared mailbox\r\n            try {\r\n                Write-Verbose \"Granting permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]\"\r\n\r\n                $sendAsPermissionSplatParams = @{\r\n                    Identity     = $mailbox.Guid\r\n                    Trustee      = $userToAdd.guid\r\n                    AccessRights = \"SendAs\"\r\n                    Confirm      = $false\r\n                    ErrorAction  = \"Stop\"\r\n                } \r\n\r\n                $addSendAsPermission = Add-RecipientPermission @sendAsPermissionSplatParams\r\n\r\n                Write-Information \"Successfully granted permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text) \r\n                    Message           = \"Successfully granted permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))\" # required (free format text) \r\n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back  \r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n            }\r\n            catch {\r\n                # Clean up error variables\r\n                $verboseErrorMessage = $null\r\n                $auditErrorMessage = $null\r\n\r\n                $ex = $PSItem\r\n                # If error message empty, fall back on $ex.Exception.Message\r\n                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n                    $verboseErrorMessage = $ex.Exception.Message\r\n                }\r\n                if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n                    $auditErrorMessage = $ex.Exception.Message\r\n                }\r\n\r\n                Write-Verbose \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text)\r\n                    Message           = \"Failed to grant permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid)). Error Message: $auditErrorMessage\" # required (free format text) \r\n                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back  \r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n                Write-Error \"Failed to grant permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid)). Error Message: $auditErrorMessage\"\r\n            }\r\n            #endregion Grant Send As to shared mailbox\r\n            break\r\n        }\r\n\r\n        \"sendonbehalf\" {\r\n            #region Grant Send on Behalf to shared mailbox\r\n            try {\r\n                Write-Verbose \"Granting permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]\"\r\n\r\n                $SendonBehalfPermissionSplatParams = @{\r\n                    Identity            = $mailbox.Guid\r\n                    GrantSendOnBehalfTo = @{ add = \"$($userToAdd.guid)\" }\r\n                    Confirm             = $false\r\n                    ErrorAction         = \"Stop\"\r\n                } \r\n\r\n                $addSendonBehalfPermission = Set-Mailbox @SendonBehalfPermissionSplatParams\r\n\r\n                Write-Information \"Successfully granted permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text) \r\n                    Message           = \"Successfully granted permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]\" # required (free format text) \r\n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back\r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n            }\r\n            catch {\r\n                # Clean up error variables\r\n                $verboseErrorMessage = $null\r\n                $auditErrorMessage = $null\r\n\r\n                $ex = $PSItem\r\n                # If error message empty, fall back on $ex.Exception.Message\r\n                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n                    $verboseErrorMessage = $ex.Exception.Message\r\n                }\r\n                if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n                    $auditErrorMessage = $ex.Exception.Message\r\n                }\r\n\r\n                Write-Verbose \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text)\r\n                    Message           = \"Failed to grant permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]. Error Message: $auditErrorMessage\" # required (free format text) \r\n                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back\r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n                Write-Error \"Error granting permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]. Error Message: $auditErrorMessage\"\r\n            }\r\n            #endregion Grant Send on Behalf to shared mailbox\r\n            break\r\n        }\r\n    }\r\n    #endregion Grant selected users permissions to shared mailbox\r\n}\r\n\r\n#region Revoke selected users permissions from shared mailbox\r\nforeach ($userToRemove in $usersToRemove) {\r\n    switch ($permission) {\r\n        \"fullaccess\" {\r\n            #region Revoke Full Access to shared mailbox\r\n            try {\r\n                Write-Verbose \"Revoking permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]\"\r\n\r\n                $FullAccessPermissionSplatParams = @{\r\n                    Identity        = $mailbox.Guid\r\n                    User            = $userToRemove.guid\r\n                    AccessRights    = \"FullAccess\"\r\n                    InheritanceType = \"All\"\r\n                    ErrorAction     = \"Stop\"\r\n                    WarningAction   = \"SilentlyContinue\"\r\n                } \r\n\r\n                $removeFullAccessPermission = Remove-MailboxPermission @FullAccessPermissionSplatParams\r\n\r\n                Write-Information \"Successfully revoked permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text) \r\n                    Message           = \"Successfully revoked permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]\" # required (free format text) \r\n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back\r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n            }\r\n            catch {\r\n                # Clean up error variables\r\n                $verboseErrorMessage = $null\r\n                $auditErrorMessage = $null\r\n\r\n                $ex = $PSItem\r\n                # If error message empty, fall back on $ex.Exception.Message\r\n                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n                    $verboseErrorMessage = $ex.Exception.Message\r\n                }\r\n                if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n                    $auditErrorMessage = $ex.Exception.Message\r\n                }\r\n\r\n                Write-Verbose \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text)\r\n                    Message           = \"Failed to revoke permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]. Error Message: $auditErrorMessage\" # required (free format text) \r\n                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back\r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n                Write-Error \"Error revoking permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]. Error Message: $auditErrorMessage\"\r\n            }\r\n            #endregion Revoke Full Access to shared mailbox\r\n            break\r\n        }\r\n            \r\n        \"sendas\" {\r\n            #region Revoke Send As to shared mailbox\r\n            try {\r\n                Write-Verbose \"Revoking permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]\"\r\n\r\n                $sendAsPermissionSplatParams = @{\r\n                    Identity     = $mailbox.Guid\r\n                    Trustee      = $userToRemove.guid\r\n                    AccessRights = \"SendAs\"\r\n                    Confirm      = $false\r\n                    ErrorAction  = \"Stop\"\r\n                } \r\n\r\n                $removeSendAsPermission = Remove-RecipientPermission @sendAsPermissionSplatParams\r\n\r\n                Write-Information \"Successfully revoked permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text) \r\n                    Message           = \"Successfully revoked permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))\" # required (free format text) \r\n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back  \r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n            }\r\n            catch {\r\n                # Clean up error variables\r\n                $verboseErrorMessage = $null\r\n                $auditErrorMessage = $null\r\n\r\n                $ex = $PSItem\r\n                # If error message empty, fall back on $ex.Exception.Message\r\n                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n                    $verboseErrorMessage = $ex.Exception.Message\r\n                }\r\n                if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n                    $auditErrorMessage = $ex.Exception.Message\r\n                }\r\n\r\n                Write-Verbose \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text)\r\n                    Message           = \"Failed to revoke permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid)). Error Message: $auditErrorMessage\" # required (free format text) \r\n                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back  \r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n                Write-Error \"Failed to revoke permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid)). Error Message: $auditErrorMessage\"\r\n            }\r\n            #endregion Revoke Send As to shared mailbox\r\n            break\r\n        }\r\n\r\n        \"sendonbehalf\" {\r\n            #region Revoke Send on Behalf to shared mailbox\r\n            try {\r\n                Write-Verbose \"Revoking permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]\"\r\n\r\n                $SendonBehalfPermissionSplatParams = @{\r\n                    Identity            = $mailbox.Guid\r\n                    GrantSendOnBehalfTo = @{ remove = \"$($userToRemove.guid)\" }\r\n                    Confirm             = $false\r\n                    ErrorAction         = \"Stop\"\r\n                } \r\n\r\n                $removeSendonBehalfPermission = Set-Mailbox @SendonBehalfPermissionSplatParams\r\n\r\n                Write-Information \"Successfully revoked permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text) \r\n                    Message           = \"Successfully revoked permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]\" # required (free format text) \r\n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back\r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n            }\r\n            catch {\r\n                # Clean up error variables\r\n                $verboseErrorMessage = $null\r\n                $auditErrorMessage = $null\r\n\r\n                $ex = $PSItem\r\n                # If error message empty, fall back on $ex.Exception.Message\r\n                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n                    $verboseErrorMessage = $ex.Exception.Message\r\n                }\r\n                if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n                    $auditErrorMessage = $ex.Exception.Message\r\n                }\r\n\r\n                Write-Verbose \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n\r\n                # Audit log for HelloID\r\n                $Log = @{\r\n                    Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"Exchange\" # optional (free format text)\r\n                    Message           = \"Failed to revoke permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]. Error Message: $auditErrorMessage\" # required (free format text) \r\n                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                }\r\n                #send result back\r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n                Write-Error \"Error revoking permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]. Error Message: $auditErrorMessage\"\r\n            }\r\n            #endregion Revoke Send on Behalf to shared mailbox\r\n            break\r\n        }\r\n    }\r\n    #endregion Revoke selected users permissions to shared mailbox\r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-pencil-square" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

