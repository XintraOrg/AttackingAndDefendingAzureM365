<#
.SYNOPSIS
    Removes all resources created by the vulnerable lab environment deployment.

.DESCRIPTION
    This cleanup script removes all intentionally vulnerable resources that were created
    by deployment.ps1, including users, groups, applications, Azure resources, and
    generated files. It provides both WhatIf mode for previewing actions and Force mode
    for automated cleanup without confirmations.

    WARNING: This script will permanently delete resources and data.
    Use with caution and ensure you have backups if needed.
    
    IMPORTANT: Some resources require manual cleanup as they were created manually:
    - Role assignments for 'Maintain User' app (User Administrator role)
    - Role assignments for Windows UAMI (Global Administrator role)
    - Azure role assignments (Contributor, Owner)
    - Access packages and catalogs (if created manually)
    - Manual Key Vault role assignments
    - Automation Account (if created manually)

.PARAMETER CountryCode
    The country code used during deployment (default: "US")

.PARAMETER AzureLocation
    The Azure region where resources were deployed (default: "westeurope")

.PARAMETER ResourceGroupName
    The name of the Azure resource group to remove (default: "default")

.PARAMETER KeyVaultName
    The name of the Azure Key Vault to remove (default: "xintrakey")

.PARAMETER AutomationAccountName
    The name of the Azure Automation Account to remove (default: "xintraautomation")

.PARAMETER LogAnalyticsWorkspaceName
    The name of the Azure Log Analytics Workspace to remove (default: "xintralog")

.PARAMETER StorageAccountName
    The name of the Azure Storage Account to remove (default: "xintrastorage")

.PARAMETER Force
    Skip confirmation prompts and perform all cleanup actions automatically

.PARAMETER WhatIf
    Show what actions would be performed without actually executing them

.EXAMPLE
    .\cleanup.ps1
    Runs interactive cleanup with confirmation prompts.

.EXAMPLE
    .\cleanup.ps1 -WhatIf
    Shows what would be cleaned up without making any changes.

.EXAMPLE
    .\cleanup.ps1 -Force
    Performs cleanup automatically without confirmation prompts.

.NOTES
    Author: Security Training Team
    Version: 1.0
    Created: $(Get-Date -Format 'yyyy-MM-dd')
    
    This script requires:
    - PowerShell 7+
    - Az PowerShell modules
    - Microsoft.Graph PowerShell module
    - Appropriate Azure/Entra ID permissions
    
    Files that will be removed:
    - created-users.csv
    - created-groups.csv
    - created-apps.csv
    - storage-access-details.csv
    
    Manual cleanup required for:
    - Entra ID role assignments
    - Azure subscription role assignments
    - Manually created access packages
    - Manual Key Vault permissions
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Country code used during deployment (e.g., US, GB, DE)")]
    [ValidateLength(2, 2)]
    [string]$CountryCode = "US",
    
    [Parameter(HelpMessage = "Azure region where resources were deployed")]
    [ValidateNotNullOrEmpty()]
    [string]$AzureLocation = "westeurope",
    
    [Parameter(HelpMessage = "Name of the Azure resource group to remove")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 90)]
    [string]$ResourceGroupName = "default",
    
    [Parameter(HelpMessage = "Name of the Azure Key Vault to remove")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(3, 24)]
    [ValidatePattern('^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$')]
    [string]$KeyVaultName = "xintrakey",
    
    [Parameter(HelpMessage = "Name of the Azure Automation Account to remove")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(6, 50)]
    [string]$AutomationAccountName = "xintraautomation",
    
    [Parameter(HelpMessage = "Name of the Azure Log Analytics Workspace to remove")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(4, 63)]
    [string]$LogAnalyticsWorkspaceName = "xintralog",
    
    [Parameter(HelpMessage = "Name of the Azure Storage Account to remove")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(3, 24)]
    [ValidatePattern('^[a-z0-9]+$')]
    [string]$StorageAccountName = "xintrastorage",
    
    [Parameter(HelpMessage = "Skip confirmation prompts and perform all cleanup actions automatically")]
    [switch]$Force,
    
    [Parameter(HelpMessage = "Show what actions would be performed without actually executing them")]
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
    Writes a timestamped log message with color coding based on level.

.DESCRIPTION
    Creates formatted log entries with timestamps and appropriate colors
    for different message types during the cleanup process.

.PARAMETER Message
    The message text to log

.PARAMETER Level
    The severity level of the message (Info, Success, Warning, Error)
    Default: "Info"

.EXAMPLE
    Write-CleanupLog "Starting cleanup process" -Level "Info"
    Write-CleanupLog "User deleted successfully" -Level "Success"
#>
function Write-CleanupLog {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Info" { "Cyan" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        default { "White" }
    }
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

<#
.SYNOPSIS
    Prompts for user confirmation before performing an action.

.DESCRIPTION
    Handles user confirmation logic, respecting WhatIf and Force modes.
    In WhatIf mode, shows what would be done. In Force mode, automatically
    confirms. Otherwise, prompts the user for confirmation.

.PARAMETER Action
    Description of the action to be performed

.OUTPUTS
    System.Boolean
    True if the action should be performed, False otherwise

.EXAMPLE
    if (Confirm-Action "delete user account") {
        # Perform the deletion
    }
#>
function Confirm-Action {
    param([string]$Action)
    if ($WhatIf) {
        Write-CleanupLog "WHATIF: Would $Action" -Level "Warning"
        return $false
    }
    if ($Force) {
        return $true
    }
    $response = Read-Host "Do you want to $Action (y/N)"
    return ($response -eq 'y' -or $response -eq 'Y')
}

<#
.SYNOPSIS
    Establishes connections to Microsoft Graph and Azure services.

.DESCRIPTION
    Imports required modules and authenticates to both Microsoft Graph
    and Azure with the necessary scopes and permissions for cleanup operations.
    Handles connection errors gracefully and provides detailed logging.

.NOTES
    This function requires admin permissions and will prompt for authentication
    if not already signed in to the required services.
#>
function Connect-ToServices {
    Write-CleanupLog "Checking modules and connections to Microsoft Graph and Azure..."
    
    # Connect to Microsoft Graph
    try {
        # Check if Microsoft Graph module is available
        $mgModule = Get-Module -Name Microsoft.Graph -ListAvailable | Select-Object -First 1
        if (-not $mgModule) {
            Write-CleanupLog "Microsoft Graph module not found. Please install it first: Install-Module Microsoft.Graph -Scope CurrentUser" -Level "Error"
            throw "Microsoft Graph module is required but not installed"
        }
        
        # Check if core Microsoft Graph modules are already loaded
        $coreGraphModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Applications')
        $loadedGraphModules = $coreGraphModules | Where-Object { Get-Module -Name $_ }
        
        if ($loadedGraphModules.Count -eq $coreGraphModules.Count) {
            Write-CleanupLog "Microsoft Graph modules already loaded" -Level "Success"
        } else {
            Write-CleanupLog "Loading Microsoft Graph module..." -Level "Info"
            Import-Module Microsoft.Graph -Force
            Write-CleanupLog "Microsoft Graph module loaded successfully" -Level "Success"
        }
        
        # Check if already connected to Microsoft Graph
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($mgContext) {
            Write-CleanupLog "Already connected to Microsoft Graph (Tenant: $($mgContext.TenantId))" -Level "Success"
            
            # Verify we have the required scopes
            $requiredScopes = @(
                "User.ReadWrite.All",
                "Directory.ReadWrite.All", 
                "RoleManagement.ReadWrite.Directory",
                "Group.ReadWrite.All",
                "Application.ReadWrite.All"
            )
            
            $currentScopes = $mgContext.Scopes
            $missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
            
            if ($missingScopes) {
                Write-CleanupLog "Current Graph connection missing required scopes: $($missingScopes -join ', ')" -Level "Warning"
                Write-CleanupLog "Reconnecting with required scopes..." -Level "Info"
                Connect-MgGraph -Scopes $requiredScopes | Out-Null
                Write-CleanupLog "Reconnected to Microsoft Graph with required scopes" -Level "Success"
            }
        } else {
            Write-CleanupLog "Connecting to Microsoft Graph..." -Level "Info"
            Connect-MgGraph -Scopes @(
                "User.ReadWrite.All",
                "Directory.ReadWrite.All", 
                "RoleManagement.ReadWrite.Directory",
                "Group.ReadWrite.All",
                "Application.ReadWrite.All"
            ) | Out-Null
            Write-CleanupLog "Connected to Microsoft Graph" -Level "Success"
        }
    } catch {
        Write-CleanupLog "Failed to connect to Microsoft Graph: $_" -Level "Error"
        throw
    }

    # Connect to Azure
    try {
        # Check for required Azure modules
        $requiredAzModules = @(
            'Az.Accounts', 'Az.Resources', 'Az.KeyVault', 'Az.Automation', 
            'Az.OperationalInsights', 'Az.Network', 'Az.Compute', 
            'Az.ManagedServiceIdentity', 'Az.Storage'
        )
        
        $missingAzModules = @()
        $loadedAzModules = @()
        
        foreach ($moduleName in $requiredAzModules) {
            $module = Get-Module -Name $moduleName -ListAvailable | Select-Object -First 1
            if (-not $module) {
                $missingAzModules += $moduleName
            } else {
                $loadedModule = Get-Module -Name $moduleName
                if (-not $loadedModule) {
                    Write-CleanupLog "Loading Azure module: $moduleName..." -Level "Info"
                    Import-Module $moduleName -Force
                    $loadedAzModules += $moduleName
                } else {
                    Write-CleanupLog "Azure module already loaded: $moduleName (Version: $($loadedModule.Version))" -Level "Success"
                }
            }
        }
        
        if ($missingAzModules) {
            Write-CleanupLog "Missing Azure modules: $($missingAzModules -join ', ')" -Level "Error"
            Write-CleanupLog "Please install missing modules: Install-Module $($missingAzModules -join ', ') -Scope CurrentUser" -Level "Error"
            throw "Required Azure modules are missing"
        }
        
        if ($loadedAzModules) {
            Write-CleanupLog "Successfully loaded Azure modules: $($loadedAzModules -join ', ')" -Level "Success"
        }
        
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($azContext) {
            Write-CleanupLog "Already connected to Azure (Subscription: $($azContext.Subscription.Name), Tenant: $($azContext.Tenant.Id))" -Level "Success"
        } else {
            Write-CleanupLog "Connecting to Azure..." -Level "Info"
            Connect-AzAccount | Out-Null
            Write-CleanupLog "Connected to Azure" -Level "Success"
        }
    } catch {
        Write-CleanupLog "Failed to connect to Azure: $_" -Level "Error"
        throw
    }
}

<#
.SYNOPSIS
    Retrieves the default domain name for the current tenant.

.DESCRIPTION
    Gets the organization information from Microsoft Graph and returns the default
    verified domain name. If no default domain is found, it falls back to the
    initial domain (.onmicrosoft.com).

.OUTPUTS
    System.String
    The default domain name for the tenant.

.EXAMPLE
    $domain = Get-TenantDefaultDomain
    Write-Output "Tenant domain: $domain"
#>
function Get-TenantDefaultDomain {
    $org = Get-MgOrganization
    $domain = ($org.VerifiedDomains | Where-Object { $_.IsDefault }).Name
    if (-not $domain) { $domain = ($org.VerifiedDomains | Where-Object { $_.IsInitial }).Name }
    if (-not $domain) { throw "Unable to determine tenant domain." }
    return $domain
}

<#
.SYNOPSIS
    Removes all users created by the lab deployment.

.DESCRIPTION
    Deletes all administrative and demo users that were created during
    the lab environment deployment. Handles cases where users may have
    already been deleted or may not exist.

.NOTES
    This function removes the following users:
    - Demo users (demo1 through demo5) - regular test users
    
    EXCLUDED from automatic deletion (require manual cleanup):
    - global.admin (Global Administrator - requires manual verification)
    - cloudapp.admin (Cloud Application Administrator - requires manual verification)
    - user.admin (User Administrator - requires manual verification)
    - privilegedrole.admin (Privileged Role Administrator - requires manual verification)
    
    All administrative users are excluded for safety and require manual deletion.
#>
function Remove-CreatedUsers {
    Write-CleanupLog "=== REMOVING USERS ===" -Level "Info"
    
    $domain = Get-TenantDefaultDomain
    $usersToRemove = @(
        "demo1@$domain",
        "demo2@$domain",
        "demo3@$domain", 
        "demo4@$domain",
        "demo5@$domain"
    )
    
    # Admin users excluded from automatic deletion (require manual cleanup)
    $excludedAdminUsers = @(
        "global.admin@$domain",
        "cloudapp.admin@$domain",
        "user.admin@$domain",
        "privilegedrole.admin@$domain"
    )
    
    Write-CleanupLog "Note: All admin users are excluded from automatic deletion for safety:" -Level "Warning"
    foreach ($excludedUser in $excludedAdminUsers) {
        Write-CleanupLog "  - $excludedUser (requires manual deletion due to administrative privileges)" -Level "Warning"
    }
    Write-CleanupLog "Only regular demo users will be automatically deleted. Admin users are listed in manual cleanup steps." -Level "Info"
    Write-CleanupLog "" -Level "Info"

    foreach ($upn in $usersToRemove) {
        try {
            Write-CleanupLog "Checking for user: $upn" -Level "Info"
            $user = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
            
            if (-not $user) {
                Write-CleanupLog "User not found: $upn" -Level "Warning"
                continue
            }

            Write-CleanupLog "Found user: $upn (ID: $($user.Id))" -Level "Info"
            
            if (Confirm-Action "remove user $upn") {
                # Verify user still exists before attempting deletion
                $userCheck = Get-MgUser -UserId $user.Id -ErrorAction SilentlyContinue
                if (-not $userCheck) {
                    Write-CleanupLog "User $upn no longer exists, skipping deletion" -Level "Warning"
                    continue
                }
                
                # Check for and remove directory role assignments
                Write-CleanupLog "Checking for directory role assignments for user: $upn" -Level "Info"
                try {
                    $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($user.Id)'" -ErrorAction SilentlyContinue
                    if ($roleAssignments -and $roleAssignments.Count -gt 0) {
                        Write-CleanupLog "Found $($roleAssignments.Count) directory role assignment(s) for user: $upn" -Level "Warning"
                        
                        foreach ($assignment in $roleAssignments) {
                            try {
                                # Get role definition details for logging
                                $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId -ErrorAction SilentlyContinue
                                $roleName = if ($roleDefinition) { $roleDefinition.DisplayName } else { $assignment.RoleDefinitionId }
                                
                                Write-CleanupLog "Removing role assignment: $roleName from user: $upn" -Level "Warning"
                                Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignment.Id
                                Write-CleanupLog "Removed role assignment: $roleName from user: $upn" -Level "Success"
                            } catch {
                                Write-CleanupLog "Failed to remove role assignment $($assignment.Id) from user $upn : $_" -Level "Error"
                            }
                        }
                        
                        # Wait a moment for role removal to propagate
                        Write-CleanupLog "Waiting for role removal to complete..." -Level "Info"
                        Start-Sleep -Seconds 5
                    } else {
                        Write-CleanupLog "No directory role assignments found for user: $upn" -Level "Info"
                    }
                } catch {
                    Write-CleanupLog "Failed to check role assignments for user $upn : $_" -Level "Warning"
                }
                
                # Check for PIM (Privileged Identity Management) eligible role assignments
                try {
                    Write-CleanupLog "Checking for PIM eligible role assignments for user: $upn" -Level "Info"
                    $pimAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($user.Id)'" -ErrorAction SilentlyContinue
                    if ($pimAssignments -and $pimAssignments.Count -gt 0) {
                        Write-CleanupLog "Found $($pimAssignments.Count) PIM eligible role assignment(s) for user: $upn" -Level "Warning"
                        
                        foreach ($pimAssignment in $pimAssignments) {
                            try {
                                $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $pimAssignment.RoleDefinitionId -ErrorAction SilentlyContinue
                                $roleName = if ($roleDefinition) { $roleDefinition.DisplayName } else { $pimAssignment.RoleDefinitionId }
                                
                                Write-CleanupLog "Removing PIM eligible role: $roleName from user: $upn" -Level "Warning"
                                Remove-MgRoleManagementDirectoryRoleEligibilitySchedule -UnifiedRoleEligibilityScheduleId $pimAssignment.Id
                                Write-CleanupLog "Removed PIM eligible role: $roleName from user: $upn" -Level "Success"
                            } catch {
                                Write-CleanupLog "Failed to remove PIM eligible role $($pimAssignment.Id) from user $upn : $_" -Level "Error"
                            }
                        }
                        
                        Start-Sleep -Seconds 5
                    } else {
                        Write-CleanupLog "No PIM eligible role assignments found for user: $upn" -Level "Info"
                    }
                } catch {
                    Write-CleanupLog "Failed to check PIM eligible roles for user $upn : $_" -Level "Warning"
                }
                
                # Check for active PIM role assignments
                try {
                    Write-CleanupLog "Checking for active PIM role assignments for user: $upn" -Level "Info"
                    $activePimAssignments = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -Filter "principalId eq '$($user.Id)'" -ErrorAction SilentlyContinue
                    if ($activePimAssignments -and $activePimAssignments.Count -gt 0) {
                        Write-CleanupLog "Found $($activePimAssignments.Count) active PIM role assignment(s) for user: $upn" -Level "Warning"
                        
                        foreach ($activePim in $activePimAssignments) {
                            try {
                                $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $activePim.RoleDefinitionId -ErrorAction SilentlyContinue
                                $roleName = if ($roleDefinition) { $roleDefinition.DisplayName } else { $activePim.RoleDefinitionId }
                                
                                Write-CleanupLog "Removing active PIM role: $roleName from user: $upn" -Level "Warning"
                                Remove-MgRoleManagementDirectoryRoleAssignmentSchedule -UnifiedRoleAssignmentScheduleId $activePim.Id
                                Write-CleanupLog "Removed active PIM role: $roleName from user: $upn" -Level "Success"
                            } catch {
                                Write-CleanupLog "Failed to remove active PIM role $($activePim.Id) from user $upn : $_" -Level "Error"
                            }
                        }
                        
                        Start-Sleep -Seconds 5
                    } else {
                        Write-CleanupLog "No active PIM role assignments found for user: $upn" -Level "Info"
                    }
                } catch {
                    Write-CleanupLog "Failed to check active PIM roles for user $upn : $_" -Level "Warning"
                }
                
                # Final verification before deletion
                $finalUserCheck = Get-MgUser -UserId $user.Id -ErrorAction SilentlyContinue
                if (-not $finalUserCheck) {
                    Write-CleanupLog "User $upn no longer exists after role cleanup, skipping deletion" -Level "Warning"
                    continue
                }
                
                # Attempt to delete the user
                try {
                    Remove-MgUser -UserId $user.Id -Confirm:$false
                    Write-CleanupLog "Removed user: $upn" -Level "Success"
                } catch {
                    if ($_.Exception.Message -like "*Insufficient privileges*" -or $_.Exception.Message -like "*Authorization_RequestDenied*") {
                        Write-CleanupLog "Still insufficient privileges to delete user $upn. This user may have roles that require manual removal." -Level "Error"
                        Write-CleanupLog "Please manually check and remove any remaining role assignments for user: $upn" -Level "Warning"
                    } else {
                        throw
                    }
                }
            }
        } catch {
            Write-CleanupLog "Failed to remove user $upn : $_" -Level "Error"
        }
    }
}

<#
.SYNOPSIS
    Removes all security groups created by the lab deployment.

.DESCRIPTION
    Deletes all permission groups and license groups that were created during
    the lab environment deployment. This includes groups for Key Vault, Automation,
    Log Analytics, Storage permissions, and license assignment groups.

.NOTES
    This function removes groups with the following patterns:
    - perm-xintra* (permission groups)
    - lic-m365-* (license groups)
    - KeyVault-* (legacy Key Vault groups)
#>
function Remove-CreatedGroups {
    Write-CleanupLog "=== REMOVING GROUPS ===" -Level "Info"
    
    $groupsToRemove = @(
        'lic-m365-e3',
        'lic-m365-P2', 
        'lic-m365-e5',
        'perm-xintrakey-reader',
        'perm-xintrakey-contributer',
        'perm-xintrakey-owner',
        'perm-xintraautomation-reader',
        'perm-xintraautomation-contributer',
        'perm-xintraautomation-owner',
        'perm-xintralog-reader',
        'perm-xintralog-contributer',
        'perm-xintralog-owner',
        'KeyVault-Secrets-Reader',
        'KeyVault-AccessPolicy-Admin',
        'perm-xintrastore-reader',
        'perm-xintrastore-contributer',
        'perm-xintrastore-owner'
    )

    foreach ($groupName in $groupsToRemove) {
        try {
            Write-CleanupLog "Checking for group: $groupName" -Level "Info"
            $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ConsistencyLevel eventual -All -ErrorAction SilentlyContinue | Select-Object -First 1
            
            if (-not $group) {
                Write-CleanupLog "Group not found: $groupName" -Level "Warning"
                continue
            }

            Write-CleanupLog "Found group: $groupName (ID: $($group.Id))" -Level "Info"
            
            if (Confirm-Action "remove group $groupName") {
                # Check if group has license assignments (for ALL groups, not just license groups)
                Write-CleanupLog "Checking for license assignments on group: $groupName" -Level "Info"
                try {
                    # Get the full group object with license details
                    $groupWithLicenses = Get-MgGroup -GroupId $group.Id -Property "id,displayName,assignedLicenses" -ErrorAction SilentlyContinue
                    
                    if ($groupWithLicenses -and $groupWithLicenses.AssignedLicenses -and $groupWithLicenses.AssignedLicenses.Count -gt 0) {
                        Write-CleanupLog "Found $($groupWithLicenses.AssignedLicenses.Count) license assignment(s) on group: $groupName" -Level "Warning"
                        
                        # Get all SKU IDs that need to be removed
                        $allSkuIds = $groupWithLicenses.AssignedLicenses | ForEach-Object { $_.SkuId }
                        
                        Write-CleanupLog "Removing all licenses from group: $groupName (SKUs: $($allSkuIds -join ', '))" -Level "Warning"
                        
                        try {
                            # Remove ALL licenses at once by specifying all SKU IDs in RemoveLicenses
                            $removeAllParams = @{
                                AddLicenses = @()
                                RemoveLicenses = $allSkuIds
                            }
                            
                            Set-MgGroupLicense -GroupId $group.Id -BodyParameter $removeAllParams
                            Write-CleanupLog "Initiated removal of all licenses from group: $groupName" -Level "Success"
                            
                            # Wait longer for license removal to complete
                            Write-CleanupLog "Waiting for license removal to propagate (20 seconds)..." -Level "Info"
                            Start-Sleep -Seconds 20
                            
                            # Verify license removal
                            $verifyGroup = Get-MgGroup -GroupId $group.Id -Property "id,displayName,assignedLicenses" -ErrorAction SilentlyContinue
                            if ($verifyGroup -and $verifyGroup.AssignedLicenses -and $verifyGroup.AssignedLicenses.Count -gt 0) {
                                Write-CleanupLog "Warning: Group $groupName still has $($verifyGroup.AssignedLicenses.Count) license(s) after removal attempt" -Level "Warning"
                                
                                # Try individual license removal as fallback
                                foreach ($remainingLicense in $verifyGroup.AssignedLicenses) {
                                    try {
                                        $individualParams = @{
                                            AddLicenses = @()
                                            RemoveLicenses = @($remainingLicense.SkuId)
                                        }
                                        Set-MgGroupLicense -GroupId $group.Id -BodyParameter $individualParams
                                        Write-CleanupLog "Individually removed license $($remainingLicense.SkuId) from group: $groupName" -Level "Success"
                                        Start-Sleep -Seconds 5
                                    } catch {
                                        Write-CleanupLog "Failed to individually remove license $($remainingLicense.SkuId) from group $groupName : $_" -Level "Error"
                                    }
                                }
                            } else {
                                Write-CleanupLog "Successfully removed all licenses from group: $groupName" -Level "Success"
                            }
                            
                        } catch {
                            Write-CleanupLog "Failed to remove licenses from group $groupName : $_" -Level "Error"
                            
                            # Try alternative approach - remove licenses one by one
                            Write-CleanupLog "Trying individual license removal for group: $groupName" -Level "Info"
                            foreach ($license in $groupWithLicenses.AssignedLicenses) {
                                try {
                                    $params = @{
                                        AddLicenses = @()
                                        RemoveLicenses = @($license.SkuId)
                                    }
                                    Set-MgGroupLicense -GroupId $group.Id -BodyParameter $params
                                    Write-CleanupLog "Removed license $($license.SkuId) from group: $groupName" -Level "Success"
                                    Start-Sleep -Seconds 5
                                } catch {
                                    Write-CleanupLog "Failed to remove license $($license.SkuId) from group $groupName : $_" -Level "Error"
                                }
                            }
                        }
                        
                    } else {
                        Write-CleanupLog "No license assignments found on group: $groupName" -Level "Info"
                    }
                } catch {
                    Write-CleanupLog "Failed to check licenses for group $groupName : $_" -Level "Warning"
                }
                
                # Verify group still exists before attempting deletion
                $groupCheck = Get-MgGroup -GroupId $group.Id -ErrorAction SilentlyContinue
                if (-not $groupCheck) {
                    Write-CleanupLog "Group $groupName no longer exists, skipping deletion" -Level "Warning"
                    continue
                }
                
                # Final license check before group deletion
                Write-CleanupLog "Performing final license check before deleting group: $groupName" -Level "Info"
                $finalLicenseCheck = Get-MgGroup -GroupId $group.Id -Property "id,displayName,assignedLicenses" -ErrorAction SilentlyContinue
                if ($finalLicenseCheck -and $finalLicenseCheck.AssignedLicenses -and $finalLicenseCheck.AssignedLicenses.Count -gt 0) {
                    Write-CleanupLog "Group $groupName still has $($finalLicenseCheck.AssignedLicenses.Count) license(s). Attempting emergency license removal..." -Level "Warning"
                    
                    # Emergency license removal
                    foreach ($license in $finalLicenseCheck.AssignedLicenses) {
                        try {
                            $emergencyParams = @{
                                AddLicenses = @()
                                RemoveLicenses = @($license.SkuId)
                            }
                            Set-MgGroupLicense -GroupId $group.Id -BodyParameter $emergencyParams
                            Write-CleanupLog "Emergency removed license $($license.SkuId) from group: $groupName" -Level "Warning"
                            Start-Sleep -Seconds 3
                        } catch {
                            Write-CleanupLog "Emergency license removal failed for $($license.SkuId): $_" -Level "Error"
                        }
                    }
                    
                    # Wait for emergency removal to propagate
                    Start-Sleep -Seconds 10
                }
                
                # Attempt to remove the group
                try {
                    Remove-MgGroup -GroupId $group.Id -Confirm:$false
                    Write-CleanupLog "Removed group: $groupName" -Level "Success"
                } catch {
                    if ($_.Exception.Message -like "*active licenses assigned*" -or $_.Exception.Message -like "*Request_BadRequest*") {
                        Write-CleanupLog "Group $groupName still has active licenses preventing deletion. Attempting final cleanup..." -Level "Error"
                        
                        # Try the most aggressive approach - get current state and remove everything
                        try {
                            $stubborn = Get-MgGroup -GroupId $group.Id -Property "id,displayName,assignedLicenses" -ErrorAction SilentlyContinue
                            if ($stubborn -and $stubborn.AssignedLicenses) {
                                Write-CleanupLog "Found stubborn licenses on group $groupName : $($stubborn.AssignedLicenses | ForEach-Object { $_.SkuId } | Join-String -Separator ', ')" -Level "Error"
                                
                                # Try to clear all licenses with empty array
                                $clearAll = @{
                                    AddLicenses = @()
                                    RemoveLicenses = @($stubborn.AssignedLicenses | ForEach-Object { $_.SkuId })
                                }
                                
                                Set-MgGroupLicense -GroupId $group.Id -BodyParameter $clearAll
                                Start-Sleep -Seconds 30  # Wait longer
                                
                                # Final deletion attempt
                                Remove-MgGroup -GroupId $group.Id -Confirm:$false
                                Write-CleanupLog "Removed group: $groupName (after stubborn license cleanup)" -Level "Success"
                            } else {
                                Write-CleanupLog "Cannot determine license state for group $groupName. Manual cleanup required." -Level "Error"
                                Write-CleanupLog "Please manually remove licenses from group '$groupName' in the Microsoft 365 admin center before deleting the group." -Level "Warning"
                            }
                        } catch {
                            Write-CleanupLog "Failed to remove group $groupName even after all license cleanup attempts: $_" -Level "Error"
                            Write-CleanupLog "MANUAL ACTION REQUIRED: Please manually remove all licenses from group '$groupName' and then delete it." -Level "Error"
                        }
                    } else {
                        throw
                    }
                }
            }
        } catch {
            Write-CleanupLog "Failed to remove group $groupName : $_" -Level "Error"
        }
    }
}

<#
.SYNOPSIS
    Removes all enterprise applications created by the lab deployment.

.DESCRIPTION
    Deletes all Azure AD enterprise applications that were created for the
    lab environment, including those with dangerous permissions and client secrets.
    This includes applications like "Office.Read", "Maintain User", and "evil automation account".

.NOTES
    This function searches for and removes applications created during deployment.
    Applications are identified by their display names and creation patterns.
#>
function Remove-EnterpriseApps {
    Write-CleanupLog "=== REMOVING ENTERPRISE APPLICATIONS ===" -Level "Info"
    
    $appsToRemove = @(
        'Office.Read',
        'Maintain User',
        'evil automation account',
        'xintra contributor app'
    )

    foreach ($appName in $appsToRemove) {
        try {
            Write-CleanupLog "Checking for application: $appName" -Level "Info"
            $app = Get-MgApplication -Filter "displayName eq '$appName'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
            
            if (-not $app) {
                Write-CleanupLog "Application not found: $appName" -Level "Warning"
                continue
            }

            Write-CleanupLog "Found application: $appName (ID: $($app.Id), AppId: $($app.AppId))" -Level "Info"
            
            if (Confirm-Action "remove application $appName") {
                # Remove service principal first if it exists
                Write-CleanupLog "Checking for service principal for: $appName" -Level "Info"
                $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($sp) {
                    Write-CleanupLog "Found service principal for: $appName, removing..." -Level "Info"
                    $spCheck = Get-MgServicePrincipal -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
                    if ($spCheck) {
                        Remove-MgServicePrincipal -ServicePrincipalId $sp.Id -Confirm:$false
                        Write-CleanupLog "Removed service principal for: $appName" -Level "Success"
                    }
                } else {
                    Write-CleanupLog "No service principal found for: $appName" -Level "Info"
                }
                
                # Verify application still exists before attempting deletion
                $appCheck = Get-MgApplication -ApplicationId $app.Id -ErrorAction SilentlyContinue
                if (-not $appCheck) {
                    Write-CleanupLog "Application $appName no longer exists, skipping deletion" -Level "Warning"
                    continue
                }
                
                # Remove application
                Remove-MgApplication -ApplicationId $app.Id -Confirm:$false
                Write-CleanupLog "Removed application: $appName" -Level "Success"
            }
        } catch {
            Write-CleanupLog "Failed to remove application $appName : $_" -Level "Error"
        }
    }
}

<#
.SYNOPSIS
    Removes all Azure resources created by the lab deployment.

.DESCRIPTION
    Deletes the entire Azure resource group and all contained resources,
    including VMs, storage accounts, Key Vault, Automation Account,
    Log Analytics workspace, networking components, and managed identities.

.PARAMETER ResourceGroupName
    The name of the resource group to delete

.NOTES
    This is a destructive operation that removes all Azure resources.
    Use with caution as this action cannot be undone.
#>
function Remove-AzureResources {
    Write-CleanupLog "=== REMOVING AZURE RESOURCES ===" -Level "Info"
    
    try {
        $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        if ($rg) {
            if (Confirm-Action "remove entire resource group '$ResourceGroupName' and ALL its contents") {
                Write-CleanupLog "Removing resource group: $ResourceGroupName (this may take several minutes)" -Level "Warning"
                Remove-AzResourceGroup -Name $ResourceGroupName -Force
                Write-CleanupLog "Removed resource group: $ResourceGroupName" -Level "Success"
            }
        } else {
            Write-CleanupLog "Resource group not found: $ResourceGroupName" -Level "Warning"
        }
    } catch {
        Write-CleanupLog "Failed to remove resource group $ResourceGroupName : $_" -Level "Error"
    }
}

<#
.SYNOPSIS
    Removes CSV files and other generated files from the lab deployment.

.DESCRIPTION
    Deletes all files that were generated during the deployment process,
    including CSV files containing user credentials, group information,
    application details, and storage access information.

.NOTES
    This function removes the following files:
    - created-users.csv
    - created-groups.csv
    - created-apps.csv
    - storage-access-details.csv
    
    These files contain sensitive information and should be securely removed.
#>
function Remove-ExportedFiles {
    Write-CleanupLog "=== REMOVING EXPORTED FILES ===" -Level "Info"
    
    $filesToRemove = @(
        "created-users.csv",
        "created-groups.csv", 
        "created-apps.csv",
        "storage-access-details.csv"
    )
    
    foreach ($fileName in $filesToRemove) {
        $filePath = Join-Path -Path $PSScriptRoot -ChildPath $fileName
        if (Test-Path $filePath) {
            if (Confirm-Action "remove export file $fileName") {
                Remove-Item $filePath -Force
                Write-CleanupLog "Removed file: $fileName" -Level "Success"
            }
        } else {
            Write-CleanupLog "File not found: $fileName" -Level "Warning"
        }
    }
}

<#
.SYNOPSIS
    Displays warnings about manual cleanup steps that must be performed.

.DESCRIPTION
    Shows a comprehensive list of resources and role assignments that were
    created manually and need to be cleaned up manually through the Azure Portal
    and Entra ID admin center.

.NOTES
    These manual steps correspond to the manual configuration steps that
    were required after running the deployment script.
#>
function Show-ManualCleanupWarnings {
    Write-CleanupLog "=== MANUAL CLEANUP REQUIRED ===" -Level "Warning"
    Write-CleanupLog "The following resources were created manually and require manual cleanup:" -Level "Warning"
    Write-CleanupLog "" -Level "Info"
    
    # Get domain for user cleanup instructions
    try {
        $domain = Get-TenantDefaultDomain
        
        Write-CleanupLog "👥 ADMIN USER ACCOUNTS:" -Level "Warning"
        Write-CleanupLog "  • Delete 'global.admin@$domain' user account" -Level "Warning"
        Write-CleanupLog "    - Navigate to Entra ID > Users > global.admin@$domain" -Level "Info"
        Write-CleanupLog "    - Remove all role assignments first, then delete the user" -Level "Info"
        Write-CleanupLog "    - WARNING: This user has Global Administrator privileges" -Level "Warning"
        Write-CleanupLog "" -Level "Info"
        
        Write-CleanupLog "  • Delete 'cloudapp.admin@$domain' user account" -Level "Warning"
        Write-CleanupLog "    - Navigate to Entra ID > Users > cloudapp.admin@$domain" -Level "Info"
        Write-CleanupLog "    - Remove all role assignments first, then delete the user" -Level "Info"
        Write-CleanupLog "    - WARNING: This user has Cloud Application Administrator privileges" -Level "Warning"
        Write-CleanupLog "" -Level "Info"
        
        Write-CleanupLog "  • Delete 'user.admin@$domain' user account" -Level "Warning"
        Write-CleanupLog "    - Navigate to Entra ID > Users > user.admin@$domain" -Level "Info"
        Write-CleanupLog "    - Remove all role assignments first, then delete the user" -Level "Info"
        Write-CleanupLog "    - WARNING: This user has User Administrator privileges" -Level "Warning"
        Write-CleanupLog "" -Level "Info"
        
        Write-CleanupLog "  • Delete 'privilegedrole.admin@$domain' user account" -Level "Warning"
        Write-CleanupLog "    - Navigate to Entra ID > Users > privilegedrole.admin@$domain" -Level "Info"
        Write-CleanupLog "    - Remove all role assignments first, then delete the user" -Level "Info"
        Write-CleanupLog "    - WARNING: This user has Privileged Role Administrator privileges" -Level "Warning"
        Write-CleanupLog "" -Level "Info"
    } catch {
        Write-CleanupLog "👥 ADMIN USER ACCOUNTS:" -Level "Warning"
        Write-CleanupLog "  • Delete 'global.admin@[your-domain]' user account manually" -Level "Warning"
        Write-CleanupLog "  • Delete 'cloudapp.admin@[your-domain]' user account manually" -Level "Warning"
        Write-CleanupLog "  • Delete 'user.admin@[your-domain]' user account manually" -Level "Warning"
        Write-CleanupLog "  • Delete 'privilegedrole.admin@[your-domain]' user account manually" -Level "Warning"
        Write-CleanupLog "    - Navigate to Entra ID > Users and remove these accounts" -Level "Info"
        Write-CleanupLog "    - Remove all role assignments first, then delete the users" -Level "Info"
        Write-CleanupLog "    - WARNING: These accounts have administrative privileges" -Level "Warning"
        Write-CleanupLog "" -Level "Info"
    }
    
    Write-CleanupLog "🔐 ENTRA ID ROLE ASSIGNMENTS:" -Level "Warning"
    Write-CleanupLog "  • Remove 'User Administrator' role from 'Maintain User' app" -Level "Warning"
    Write-CleanupLog "    - Navigate to Entra ID > Enterprise Applications > 'Maintain User' > App roles" -Level "Info"
    Write-CleanupLog "    - Remove User Administrator role assignment" -Level "Info"
    Write-CleanupLog "" -Level "Info"
    
    Write-CleanupLog "  • Remove 'Global Administrator' role from Windows UAMI" -Level "Warning"
    Write-CleanupLog "    - Navigate to Entra ID > Roles and administrators > Global Administrator" -Level "Info"
    Write-CleanupLog "    - Find and remove the Windows VM managed identity assignment" -Level "Info"
    Write-CleanupLog "" -Level "Info"
    
    Write-CleanupLog "🏢 AZURE SUBSCRIPTION ROLE ASSIGNMENTS:" -Level "Warning"
    Write-CleanupLog "  • Remove 'Contributor' role from 'xintra contributor app'" -Level "Warning"
    Write-CleanupLog "  • Remove 'Owner' role from 'xintra-owner-uami'" -Level "Warning"
    Write-CleanupLog "    - Navigate to Azure Portal > Subscriptions > Your subscription > Access control (IAM)" -Level "Info"
    Write-CleanupLog "    - Find and remove these role assignments" -Level "Info"
    Write-CleanupLog "" -Level "Info"
    
    Write-CleanupLog "📦 ACCESS PACKAGES (if created manually):" -Level "Warning"
    Write-CleanupLog "  • Remove 'xintra access' access package" -Level "Warning"
    Write-CleanupLog "  • Remove 'xintra access' catalog" -Level "Warning"
    Write-CleanupLog "    - Navigate to Entra ID > Identity Governance > Access packages" -Level "Info"
    Write-CleanupLog "    - Note: Access package cleanup requires manual removal due to module dependencies" -Level "Info"
    Write-CleanupLog "" -Level "Info"
    
    Write-CleanupLog "🔑 KEY VAULT PERMISSIONS:" -Level "Warning"
    Write-CleanupLog "  • Remove manual 'Key Vault Secrets Officer' role assignments" -Level "Warning"
    Write-CleanupLog "    - Navigate to Key Vault > Access control (IAM)" -Level "Info"
    Write-CleanupLog "    - Remove any manually assigned permissions" -Level "Info"
    Write-CleanupLog "" -Level "Info"
    
    Write-CleanupLog "⚙️ AUTOMATION ACCOUNT (if created manually):" -Level "Warning"
    Write-CleanupLog "  • Remove manually created Automation Account" -Level "Warning"
    Write-CleanupLog "    - Navigate to Azure Portal > Automation Accounts" -Level "Info"
    Write-CleanupLog "    - Delete the manually created account" -Level "Info"
    Write-CleanupLog "" -Level "Info"
    
    Write-CleanupLog "📊 STORAGE CONTAINER:" -Level "Warning"
    Write-CleanupLog "  • Public container should be removed with the storage account" -Level "Info"
    Write-CleanupLog "  • If storage account still exists, manually remove 'public' container" -Level "Info"
    Write-CleanupLog "" -Level "Info"
    
    Write-CleanupLog "⚠️  These items cannot be automatically cleaned up and must be removed manually" -Level "Error"
    Write-CleanupLog "    to ensure complete lab environment removal." -Level "Error"
}

# Main execution
Write-CleanupLog "=== XINTRA LAB CLEANUP SCRIPT ===" -Level "Info"

if ($WhatIf) {
    Write-CleanupLog "Running in WHATIF mode - no changes will be made" -Level "Warning"
}

if (-not $Force -and -not $WhatIf) {
    Write-CleanupLog "WARNING: This script will remove all resources created by deployment.ps1" -Level "Warning"
    Write-CleanupLog "This includes:" -Level "Warning"
    Write-CleanupLog "  - All created users and their data" -Level "Warning"
    Write-CleanupLog "  - All security groups" -Level "Warning"
    Write-CleanupLog "  - All enterprise applications" -Level "Warning"
    Write-CleanupLog "  - The entire Azure resource group '$ResourceGroupName' and ALL resources within it" -Level "Warning"
    Write-CleanupLog "  - Access packages and catalogs" -Level "Warning"
    Write-CleanupLog "  - Exported CSV files" -Level "Warning"
    Write-CleanupLog "" -Level "Info"
    $confirm = Read-Host "Are you absolutely sure you want to continue? Type 'DELETE' to confirm"
    if ($confirm -ne "DELETE") {
        Write-CleanupLog "Cleanup cancelled by user" -Level "Info"
        exit 0
    }
}

try {
    Connect-ToServices
    
    Write-CleanupLog "Starting automated cleanup process..." -Level "Info"
    
    # Clean up in reverse order of creation
    Remove-ExportedFiles
    Remove-AzureResources
    Remove-EnterpriseApps
    Remove-CreatedGroups
    Remove-CreatedUsers
    
    Write-CleanupLog "=== AUTOMATED CLEANUP COMPLETED ===" -Level "Success"
    Write-CleanupLog "All automatically created xintra lab resources have been removed" -Level "Success"
    Write-CleanupLog "" -Level "Info"
    
    # Show manual cleanup requirements
    Show-ManualCleanupWarnings
    
} catch {
    Write-CleanupLog "Cleanup failed with error: $_" -Level "Error"
    Write-CleanupLog "You may need to manually clean up remaining resources" -Level "Warning"
    
    # Still show manual cleanup warnings even if automated cleanup failed
    Write-CleanupLog "" -Level "Info"
    Show-ManualCleanupWarnings
    
    exit 1
}