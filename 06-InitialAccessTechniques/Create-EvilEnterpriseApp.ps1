# Requires: Microsoft.Graph PowerShell module
# Permissions: Application Administrator or Global Administrator

Import-Module Microsoft.Graph.Applications

# Connect to Microsoft Graph (interactive login)
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Create the application registration (multitenant, with web redirect URI)
$app = New-MgApplication -DisplayName "Office.Read" -SignInAudience "AzureADMultipleOrgs" `
    -Web @{ RedirectUris = @("http://localhost:5000/getAToken") }
Write-Host "Created application registration: $($app.DisplayName) (AppId: $($app.AppId))"

# Create the service principal (enterprise application)
$sp = New-MgServicePrincipal -AppId $app.AppId
Write-Host "Created enterprise application: $($sp.DisplayName) (ObjectId: $($sp.Id))"

# Generate a client secret for the application
$secret = Add-MgApplicationPassword -ApplicationId $app.Id -DisplayName "DefaultSecret"
Write-Host "Client secret generated. Value: $($secret.SecretText)"

# Print client secret, client id, and tenant id at the end
$tenantId = (Get-MgContext).TenantId
Write-Host "`n--- Application Credentials ---"
Write-Host "Client ID: $($app.AppId)"
Write-Host "Client Secret: $($secret.SecretText)"
Write-Host "Tenant ID: $tenantId"
