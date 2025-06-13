# Requires: Microsoft.Graph PowerShell module
# Permissions: Identity Governance Administrator or Global Administrator
# This script creates an Access Package using Microsoft Graph.

Import-Module Microsoft.Graph.Identity.Governance, Microsoft.Graph.Identity.DirectoryManagement
# Ensure the Microsoft Graph PowerShell module is installed
if (-not (Get-Module -Name Microsoft.Graph -ListAvailable)) {
    Write-Host "Microsoft Graph PowerShell module is not installed. Please install it using 'Install-Module Microsoft.Graph'."
    exit
}

# Connect to Microsoft Graph (interactive login)
Connect-MgGraph -Scopes "EntitlementManagement.ReadWrite.All, Application.Read.All"

# Define Access Package properties
$displayName = "My Access Package"
$description = "Access package created via Microsoft Graph PowerShell"

# Try to get a writable catalog
$catalog = Get-MgEntitlementManagementAccessPackageCatalog | Where-Object { $_.IsWritable -eq $true } | Select-Object -First 1

if (-not $catalog) {
    Write-Host "No writable Access Package Catalog found. Creating a new catalog..."
    $catalogDisplayName = "My Access Package Catalog"
    $catalogDescription = "Catalog created via Microsoft Graph PowerShell"
    $catalog = New-MgEntitlementManagementAccessPackageCatalog -DisplayName $catalogDisplayName -Description $catalogDescription -IsWritable $true
    Write-Host "Created Catalog: $($catalog.DisplayName) (ID: $($catalog.Id))"
}

$catalogId = $catalog.Id

# Create the Access Package
$accessPackage = New-MgEntitlementManagementAccessPackage -DisplayName $displayName `
    -Description $description `
    -CatalogId $catalogId

Write-Host "Created Access Package: $($accessPackage.DisplayName) (ID: $($accessPackage.Id))"

# Add all present enterprise applications as resources to the access package with default access
Import-Module Microsoft.Graph.Applications

$applications = Get-MgServicePrincipal

foreach ($app in $applications) {
    try {
        # Add the application as a resource to the access package catalog if not already present
        $resource = Get-MgEntitlementManagementAccessPackageResource -CatalogId $catalogId -Filter "originId eq '$($app.Id)' and originSystem eq 'AadApplication'" -ErrorAction SilentlyContinue
        if (-not $resource) {
            $resource = New-MgEntitlementManagementAccessPackageResourceRequest -CatalogId $catalogId -RequestType "AdminAdd" -ResourceType "AadApplication" -OriginId $app.Id
            Write-Host "Added application $($app.DisplayName) as resource to catalog."
        }

        # Grant default access (all roles) to the access package for this application
        $roles = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $app.Id
        foreach ($role in $roles) {
            New-MgEntitlementManagementAccessPackageResourceRoleScope -AccessPackageId $accessPackage.Id `
                -CatalogId $catalogId `
                -AccessPackageResourceRoleId $role.Id `
                -AccessPackageResourceScopeId $role.ResourceId | Out-Null
        }
    } catch {
        Write-Warning "Failed to add application $($app.DisplayName): $_"
    }
}