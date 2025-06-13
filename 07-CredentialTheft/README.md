# Automated Deployment: Key Vault, Automation Account, and Log Analytics Workspace

This solution deploys the following resources into a resource group named `default`:

- Azure Key Vault (`xintrakey`)
- Azure Automation Account (`xintraautomation`)
- Azure Log Analytics Workspace (`xintralog`)

## Deployment via ARM Template

You can deploy all resources using the provided ARM template:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FXintraOrg%2FAttackingAndDefendingAzureM365%2Fmain%2F07-CredentialTheft%2Finfrastructure-arm.json)

### Parameters

- `location`: Azure region
- `keyVaultName`: Name for the Key Vault
- `automationAccountName`: Name for the Automation Account
- `logAnalyticsWorkspaceName`: Name for the Log Analytics Workspace
- `automationOwnerGroupObjectId`: ObjectId of the group to be assigned Owner on the Automation Account
- `automationContributorGroupObjectId`: ObjectId of the group to be assigned Contributor on the Automation Account

## Deployment via PowerShell

You can also deploy using PowerShell and the Az module:

```powershell
.\Deploy-Infrastructure.ps1
```

This script will:
- Deploy the infrastructure using the ARM template.
- Create Entra ID groups for Key Vault access (secrets reader and access policy admin).
- Assign RBAC roles to these groups for the Key Vault.
- Create two groups for Automation Account (Owner and Contributor) and assign the corresponding permissions via ARM template parameters.
- Set up diagnostic settings for the Key Vault to send logs to Log Analytics.
- Generate a credential in the Automation Account named `superSecureXintraAutomation` with a random password and display it.

#### Prerequisites

- Az PowerShell module installed and authenticated (`Connect-AzAccount`)
- Microsoft.Graph PowerShell module installed and authenticated
- Sufficient permissions to create resource groups, deploy ARM templates, manage Entra ID groups, and assign RBAC roles