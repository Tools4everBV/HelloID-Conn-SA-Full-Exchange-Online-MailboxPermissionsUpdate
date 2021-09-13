<!-- Version -->
## Version
Version 1.0.0.
> __This is the initial version, please let us know about any bugs/features!__

<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides Exchange Online (Office365) mailbox functionality. The following steps will be performed:
 1. Search and select the target
 2. Select a permission (Full Access, Send As or Send on Behalf)
 3. Modify users with permissions
 4. After confirmation the updates are processed (add or remove premissions)
 
<!-- TABLE OF CONTENTS -->
## Table of Contents
- [HelloID-Conn-SA-Source-HelloID-SelfserviceProducts](#helloid-conn-sa-source-helloid-selfserviceproducts)
  - [Version](#version)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  - [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Post-setup configuration](#post-setup-configuration)
  - [Post-setup configuration](#post-setup-configuration-1)
  - [Manual resources](#manual-resources)
    - [Powershell data source 'exchange-online-shared-mailbox-manage-permissions-generate-table-mailbox-wildcard'](#powershell-data-source-exchange-online-shared-mailbox-manage-permissions-generate-table-mailbox-wildcard)
    - [Powershell data source 'Exchange-user-generate-table-sharedmailbox-manage-generate-table-users-permission'](#powershell-data-source-exchange-user-generate-table-sharedmailbox-manage-generate-table-users-permission)
    - [Powershell data source 'Exchange-user-generate-table-sharedmailbox-manage-generate-table-users'](#powershell-data-source-exchange-user-generate-table-sharedmailbox-manage-generate-table-users)
    - [Delegated form task 'exchange-online-shared-mailbox-manage-permissions-set'](#delegated-form-task-exchange-online-shared-mailbox-manage-permissions-set)
- [HelloID Docs](#helloid-docs)
- [Forum Thread](#forum-thread)

## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_

## Getting started

### Prerequisites

- [ ] Exchange Online PowerShell V2 module
  This HelloID Service Automation Delegated Form uses the [Exchange Online PowerShell V2 module](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)

### Post-setup configuration
| Variable name                 | Description               | Example value     |
| ----------------------------- | ------------------------- | ----------------- |
| ExchangeOnlineAdminUsername   |Exchange admin account     | user@domain.com   |
| ExchangeOnlineAdminPassword   | Exchange admin password   | ********          |


## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source 'exchange-online-shared-mailbox-manage-permissions-generate-table-mailbox-wildcard'
This Static data source the domain name for the mail address of the mailbox.

### Powershell data source 'Exchange-user-generate-table-sharedmailbox-manage-generate-table-users-permission'
This Static data source the domain name for the mail address of the mailbox.

### Powershell data source 'Exchange-user-generate-table-sharedmailbox-manage-generate-table-users'
This Static data source the domain name for the mail address of the mailbox.

### Delegated form task 'exchange-online-shared-mailbox-manage-permissions-set'
This delegated form task will create the shared mailbox in Exchange.

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/

# Forum Thread
The Forum thread for any questions or remarks regarding this connector can be found at: https://forum.helloid.com/forum/helloid-connectors/service-automation/290-helloid-sa-exchange-online-update-user
