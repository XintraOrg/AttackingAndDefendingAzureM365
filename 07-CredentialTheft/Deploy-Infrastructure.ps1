# Prerequisites: Az PowerShell module installed and authenticated

$resourceGroup = "default"
$location = "westeurope"
$keyVaultName = "xintrakey"
$automationAccountName = "xintraautomation"
$logAnalyticsWorkspaceName = "xintralog"
$templateFile = "$PSScriptRoot/infrastructure-arm.json"

Import-Module Az.Accounts
Import-Module Az.Resources
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Users

if (-not (Get-AzContext)) {
    Connect-AzAccount
}

if (-not (Get-AzResourceGroup -Name $resourceGroup -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $resourceGroup -Location $location | Out-Null
}

# Deploy infrastructure
New-AzResourceGroupDeployment -ResourceGroupName $resourceGroup -TemplateFile $templateFile `
    -location $location `
    -keyVaultName $keyVaultName `
    -automationAccountName $automationAccountName `
    -logAnalyticsWorkspaceName $logAnalyticsWorkspaceName | Out-Null

# Create two Entra ID groups
Connect-MgGraph -Scopes "Group.ReadWrite.All"
$secretsReaderGroup = New-MgGroup -DisplayName "KeyVault-Secrets-Reader" -MailEnabled:$false -MailNickname "kvsecretsreader" -SecurityEnabled:$true
$accessPolicyAdminGroup = New-MgGroup -DisplayName "KeyVault-AccessPolicy-Admin" -MailEnabled:$false -MailNickname "kvaccesspolicyadmin" -SecurityEnabled:$true

# Assign RBAC roles to the groups for the Key Vault
$keyVault = Get-AzKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroup

# Ensure all required role definitions are available
$requiredRoles = @(
    "Key Vault Secrets User",
    "Key Vault Access Policy Administrator"
)
foreach ($role in $requiredRoles) {
    if (-not (Get-AzRoleDefinition -Name $role -ErrorAction SilentlyContinue)) {
        Write-Host "Role definition '$role' not found. Importing built-in role definitions is required for this deployment."
        # Normally, built-in roles are present. If missing, user must import or wait for Azure propagation.
    }
}

# Ensure Microsoft.KeyVault, Microsoft.Automation, and Microsoft.OperationalInsights resource providers are registered
$providers = @("Microsoft.KeyVault", "Microsoft.Automation", "Microsoft.OperationalInsights")
foreach ($provider in $providers) {
    $reg = Get-AzResourceProvider -ProviderNamespace $provider
    if ($reg.RegistrationState -ne "Registered") {
        Register-AzResourceProvider -ProviderNamespace $provider | Out-Null
        Write-Host "Registering resource provider: $provider"
    }
}

# Key Vault Secrets User (read secrets)
New-AzRoleAssignment -ObjectId $secretsReaderGroup.Id `
    -RoleDefinitionName "Key Vault Secrets User" `
    -Scope $keyVault.ResourceId | Out-Null

# Key Vault Access Policy Administrator (read and modify access policies)
New-AzRoleAssignment -ObjectId $accessPolicyAdminGroup.Id `
    -RoleDefinitionName "Key Vault Access Policy Administrator" `
    -Scope $keyVault.ResourceId | Out-Null

# Generate credentials for the Automation Account
$automationCredentialName = "superSecureXintraAutomation"
$automationCredentialUser = "superSecureXintraAutomation"
# Generate a random password (16 chars, alphanumeric + special)
Add-Type -AssemblyName System.Web
$automationCredentialPassword = [System.Web.Security.Membership]::GeneratePassword(16,3)

# Create the credential in the Automation Account
$securePassword = ConvertTo-SecureString $automationCredentialPassword -AsPlainText -Force
$automationCredential = New-AzAutomationCredential -ResourceGroupName $resourceGroup `
    -AutomationAccountName $automationAccountName `
    -Name $automationCredentialName `
    -UserName $automationCredentialUser `
    -Password $securePassword

Write-Host "`n--- Automation Account Credential ---"
Write-Host "Credential Name: $automationCredentialName"
Write-Host "Username: $automationCredentialUser"
Write-Host "Password: $automationCredentialPassword"

Write-Host "Deployment complete. Groups and permissions assigned."
