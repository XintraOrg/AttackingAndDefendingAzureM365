<#
.SYNOPSIS
    Deploys intentionally vulnerable Microsoft 365 and Azure lab environment for security training.

.DESCRIPTION
    This script creates a comprehensive vulnerable lab environment with intentional security flaws
    for educational purposes. It deploys users, groups, applications, Azure resources, and managed
    identities with dangerous permissions for security training exercises.

    WARNING: This script creates INTENTIONALLY VULNERABLE resources with CRITICAL SECURITY FLAWS.
    DO NOT USE IN PRODUCTION ENVIRONMENTS.

.PARAMETER CountryCode
    The country code for user creation (default: "US")

.PARAMETER AzureLocation
    The Azure region where resources will be deployed (default: "westeurope")

.PARAMETER ResourceGroupName
    The name of the Azure resource group to create (default: "default")

.PARAMETER KeyVaultName
    The name of the Azure Key Vault to create (default: "xintrakey")

.PARAMETER AutomationAccountName
    The name of the Azure Automation Account to create (default: "xintraautomation")

.PARAMETER LogAnalyticsWorkspaceName
    The name of the Azure Log Analytics Workspace to create (default: "xintralog")

.PARAMETER StorageAccountName
    The name of the Azure Storage Account to create (default: "xintrastorage")
    Must be globally unique, 3-24 lowercase letters/numbers only.

.EXAMPLE
    .\deployment.ps1
    Deploys the lab environment with default parameters.

.EXAMPLE
    .\deployment.ps1 -AzureLocation "eastus" -ResourceGroupName "lab-env"
    Deploys the lab environment in East US region with custom resource group name.

.NOTES
    Author: Security Training Team
    Version: 1.0
    Created: $(Get-Date -Format 'yyyy-MM-dd')
    
    This script requires:
    - PowerShell 7+
    - Az PowerShell modules
    - Microsoft.Graph PowerShell module
    - Appropriate Azure/Entra ID permissions
    
    Generated Files:
    - created-users.csv
    - created-groups.csv
    - created-apps.csv
    - storage-access-details.csv
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Country code for user creation (e.g., US, GB, DE)")]
    [ValidateLength(2, 2)]
    [string]$CountryCode = "US",
    
    [Parameter(HelpMessage = "Azure region where resources will be deployed")]
    [ValidateNotNullOrEmpty()]
    [string]$AzureLocation = "westeurope",
    
    [Parameter(HelpMessage = "Name of the Azure resource group to create")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 90)]
    [string]$ResourceGroupName = "default",
    
    [Parameter(HelpMessage = "Name of the Azure Key Vault to create")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(3, 24)]
    [ValidatePattern('^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$')]
    [string]$KeyVaultName = "xintrakey",
    
    [Parameter(HelpMessage = "Name of the Azure Automation Account to create")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(6, 50)]
    [string]$AutomationAccountName = "xintraautomation",
    
    [Parameter(HelpMessage = "Name of the Azure Log Analytics Workspace to create")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(4, 63)]
    [string]$LogAnalyticsWorkspaceName = "xintralog",
    
    [Parameter(HelpMessage = "Name of the Azure Storage Account to create (globally unique, lowercase letters/numbers only)")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(3, 24)]
    [ValidatePattern('^[a-z0-9]+$')]
    [string]$StorageAccountName = "xintrastorage"
)

# =======================================
# CRITICAL SECURITY WARNING & CONFIRMATION
# =======================================

Write-Host ""
Write-Host "⚠️  CRITICAL SECURITY WARNING ⚠️" -ForegroundColor Red -BackgroundColor Yellow
Write-Host ""
Write-Host "🚨 This script will deploy INTENTIONALLY VULNERABLE resources with CRITICAL SECURITY FLAWS:" -ForegroundColor Red
Write-Host "   • Users with weak password policies" -ForegroundColor Yellow
Write-Host "   • Enterprise apps with excessive permissions and long-lived secrets" -ForegroundColor Yellow
Write-Host "   • Storage accounts with public access and leaked credentials" -ForegroundColor Yellow
Write-Host "   • Managed identities with subscription-wide Owner privileges" -ForegroundColor Yellow
Write-Host "   • VMs exposed to the Internet with weak network security" -ForegroundColor Yellow
Write-Host "   • Permissive RBAC assignments and auto-approval access packages" -ForegroundColor Yellow
Write-Host ""
Write-Host "⛔ DO NOT USE IN PRODUCTION ENVIRONMENTS" -ForegroundColor Red -BackgroundColor White
Write-Host "✅ ONLY FOR SECURITY TRAINING AND EDUCATIONAL PURPOSES" -ForegroundColor Green
Write-Host ""
Write-Host "Resources will be created in:" -ForegroundColor Cyan
Write-Host "   • Resource Group: '$ResourceGroupName'" -ForegroundColor White
Write-Host "   • Azure Location: '$AzureLocation'" -ForegroundColor White
Write-Host "   • Storage Account: '$StorageAccountName'" -ForegroundColor White
Write-Host "   • Key Vault: '$KeyVaultName'" -ForegroundColor White
Write-Host ""

do {
    $confirmation = Read-Host "⚠️  Type 'deploy' to confirm deployment of vulnerable resources (or 'cancel' to exit)"
    if ($confirmation -eq "cancel") {
        Write-Host "Deployment cancelled by user." -ForegroundColor Green
        exit 0
    }
    elseif ($confirmation -ne "deploy") {
        Write-Host "Invalid input. Please type 'deploy' to continue or 'cancel' to exit." -ForegroundColor Yellow
    }
} while ($confirmation -ne "deploy")

Write-Host ""
Write-Host "✅ Deployment confirmed. Proceeding with vulnerable resource creation..." -ForegroundColor Green
Write-Host ""

Set-StrictMode -Version 2.0  # Reduced from Latest to avoid runspace issues
$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
    Ensures Microsoft Graph PowerShell module is installed and imported.

.DESCRIPTION
    Checks if the Microsoft.Graph module is available, installs it if missing,
    imports the module, and selects the v1.0 profile for API compatibility.

.NOTES
    This function uses CurrentUser scope for installation to avoid requiring
    administrator privileges.
#>
function Install-GraphModule {
    [CmdletBinding()]
    param()
    
    try {
        # Check if Microsoft Graph Authentication module is available (core module)
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
            Write-Host "Installing required Microsoft Graph modules..." -ForegroundColor Cyan
            
            # Install specific Graph modules instead of the monolithic package to avoid conflicts
            $requiredModules = @(
                'Microsoft.Graph.Authentication',
                'Microsoft.Graph.Applications', 
                'Microsoft.Graph.Users',
                'Microsoft.Graph.Groups',
                'Microsoft.Graph.Identity.DirectoryManagement',
                'Microsoft.Graph.Identity.Governance'
            )
            
            foreach ($module in $requiredModules) {
                Write-Host "Installing $module..." -ForegroundColor Gray
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            }
        } else {
            Write-Host "Microsoft Graph modules already installed, checking availability..." -ForegroundColor Green
        }
        
        # Import required modules if not already imported
        $modulesList = @(
            'Microsoft.Graph.Authentication',
            'Microsoft.Graph.Users',
            'Microsoft.Graph.Groups',
            'Microsoft.Graph.Applications',
            'Microsoft.Graph.Identity.DirectoryManagement',
            'Microsoft.Graph.Identity.Governance'
        )
        
        foreach ($module in $modulesList) {
            if (-not (Get-Module -Name $module)) {
                Write-Host "Importing $module..." -ForegroundColor Cyan
                try {
                    Import-Module $module -Force -ErrorAction Stop
                } catch {
                    Write-Warning "Failed to import $module : $($_.Exception.Message)"
                }
            }
        }
        
        # Note: Select-MgProfile is deprecated in newer versions of Microsoft Graph PowerShell
        # The v1.0 profile is now the default, so we don't need to explicitly select it
        
        Write-Host "Microsoft Graph modules ready for use." -ForegroundColor Green
        Write-Verbose "Microsoft Graph module installed and imported successfully"
    }
    catch {
        Write-Error "Failed to install or import Microsoft Graph module: $($_.Exception.Message)"
        throw
    }
}

<#
.SYNOPSIS
    Connects to Microsoft Graph with required permission scopes.

.DESCRIPTION
    Establishes a connection to Microsoft Graph with the specific scopes needed
    for the lab deployment, including user management, directory access, role
    management, group management, application management, and entitlement management.

.NOTES
    This function requires admin consent for the requested scopes.
    The connection will prompt for interactive authentication if needed.
#>
function Connect-ToMicrosoftGraph {
    [CmdletBinding()]
    param()
    
    $requiredScopes = @(
        "User.ReadWrite.All",
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Group.ReadWrite.All",
        "Application.ReadWrite.All",
        "EntitlementManagement.ReadWrite.All" # Added for Access Package (Identity Governance)
    )
    
    try {
        # Check if already connected to Microsoft Graph
        $currentContext = Get-MgContext -ErrorAction SilentlyContinue
        
        if ($currentContext) {
            Write-Host "Already connected to Microsoft Graph as: $($currentContext.Account)" -ForegroundColor Green
            
            # Check if we have the required scopes
            $currentScopes = $currentContext.Scopes
            $missingScopes = @()
            
            foreach ($scope in $requiredScopes) {
                if ($scope -notin $currentScopes) {
                    $missingScopes += $scope
                }
            }
            
            if ($missingScopes.Count -eq 0) {
                Write-Host "All required scopes are already granted." -ForegroundColor Green
                Write-Verbose "Successfully verified Microsoft Graph connection with required scopes"
                return
            } else {
                Write-Host "Current connection missing required scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
                Write-Host "Reconnecting with additional scopes..." -ForegroundColor Cyan
                Disconnect-MgGraph | Out-Null
            }
        }
        
        Write-Host "Connecting to Microsoft Graph with required scopes..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes $requiredScopes | Out-Null
        
        # Verify the connection was successful
        $newContext = Get-MgContext
        if ($newContext) {
            Write-Host "Successfully connected to Microsoft Graph as: $($newContext.Account)" -ForegroundColor Green
            Write-Verbose "Successfully connected to Microsoft Graph with required scopes"
        } else {
            throw "Failed to establish Microsoft Graph connection"
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
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
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    try {
        $org = Get-MgOrganization
        $domain = ($org.VerifiedDomains | Where-Object { $_.IsDefault }).Name
        if (-not $domain) { 
            $domain = ($org.VerifiedDomains | Where-Object { $_.IsInitial }).Name 
        }
        if (-not $domain) { 
            throw "Unable to determine tenant domain from organization data"
        }
        Write-Verbose "Found tenant domain: $domain"
        return $domain
    }
    catch {
        Write-Error "Failed to retrieve tenant default domain: $($_.Exception.Message)"
        throw
    }
}

<#
.SYNOPSIS
    Generates a strong password with specified requirements.

.DESCRIPTION
    Creates a secure password with a mix of uppercase letters, lowercase letters,
    digits, and special characters. Ensures the password meets complexity requirements
    by including at least one character from each category.

.PARAMETER Length
    The desired length of the password (default: 16)

.PARAMETER MinNonAlpha
    Minimum number of non-alphabetic characters required (default: 3)

.OUTPUTS
    System.String
    A strong password meeting the specified requirements.

.EXAMPLE
    $password = New-StrongPassword
    Creates a 16-character password with default complexity.

.EXAMPLE
    $password = New-StrongPassword -Length 20 -MinNonAlpha 5
    Creates a 20-character password with at least 5 special characters.
#>
function New-StrongPassword {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(HelpMessage = "Length of the password to generate")]
        [ValidateRange(8, 128)]
        [int]$Length = 16,
        
        [Parameter(HelpMessage = "Minimum number of non-alphabetic characters")]
        [ValidateRange(1, 10)]
        [int]$MinNonAlpha = 3
    )
    
    $upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $lower = "abcdefghijkmnopqrstuvwxyz"
    $digits = "23456789"
    $special = "!@#$%^&*()-_=+[]{}:,.?"
    $all = ($upper + $lower + $digits + $special).ToCharArray()

    do {
        $chars = @()
        $chars += ($upper.ToCharArray() | Get-Random -Count 1)
        $chars += ($lower.ToCharArray() | Get-Random -Count 1)
        $chars += ($digits.ToCharArray() | Get-Random -Count 1)
        $chars += ($special.ToCharArray() | Get-Random -Count $MinNonAlpha)
        $remaining = $Length - $chars.Count
        if ($remaining -gt 0) { 
            $chars += ($all | Get-Random -Count $remaining) 
        }
        $password = -join ($chars | Get-Random -Count $chars.Count)
        
        $hasUpper = $password -cmatch '[A-Z]'
        $hasLower = $password -cmatch '[a-z]'
        $hasDigit = $password -match '\d'
        $hasSpecial = $password -match '[^A-Za-z0-9]'
        $hasCorrectLength = $password.Length -eq $Length
        
        $isValid = $hasUpper -and $hasLower -and $hasDigit -and $hasSpecial -and $hasCorrectLength
    } while (-not $isValid)
    
    Write-Verbose "Generated strong password with length: $($password.Length)"
    return $password
}

<#
.SYNOPSIS
    Creates a new user in the Azure AD tenant.

.DESCRIPTION
    Creates a user with the specified username and assigns them to license groups.
    This function is specifically designed for creating lab users with intentionally
    weak security settings for training purposes.

.PARAMETER UserPrincipalName
    The UPN of the user to create

.PARAMETER DisplayName
    The display name for the user

.PARAMETER Domain
    The tenant domain name

.PARAMETER Password
    The password for the user account

.OUTPUTS
    Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser
    The created user object
#>
function New-LabUser {
    param(
        [Parameter(Mandatory)] [string]$UserPrincipalName,
        [Parameter(Mandatory)] [string]$DisplayName,
        [Parameter(Mandatory)] [string]$MailNickname,
        [string]$Country = $CountryCode
    )
    try {
        $user = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
        return New-Object PSObject -Property @{ User = $user; Created = $false; Password = $null }
    } catch {
        # Create user
        $password = New-StrongPassword
        $userParams = @{
            AccountEnabled   = $true
            DisplayName      = $DisplayName
            MailNickname     = $MailNickname
            UserPrincipalName= $UserPrincipalName
            PasswordProfile  = @{
                Password = $password
                ForceChangePasswordNextSignIn = $true
            }
            UsageLocation    = $Country
        }
        $user = New-MgUser @userParams
        return New-Object PSObject -Property @{ User = $user; Created = $true; Password = $password }
    }
}

# Map friendly role names to their well-known template IDs
$RoleTemplateMap = @{
    "Global Administrator"             = "62e90394-69f5-4237-9190-012177145e10"
    "Cloud Application Administrator"  = "158c047a-c907-4556-b7ef-446551a6b5f7"
    "User Administrator"               = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    "Privileged Role Administrator"    = "e8611ab8-c189-46e8-94e1-60213ab1f814"
}

<#
.SYNOPSIS
    Ensures a directory role is activated in Azure AD.

.DESCRIPTION
    Activates the specified directory role if it's not already active.
    This is required before assigning users to certain administrative roles.

.PARAMETER RoleName
    The name of the directory role to activate

.OUTPUTS
    Microsoft.Graph.PowerShell.Models.MicrosoftGraphDirectoryRole
    The activated directory role object
#>
function Enable-DirectoryRole {
    param([Parameter(Mandatory)] [string]$DisplayName)
    $role = Get-MgDirectoryRole | Where-Object DisplayName -eq $DisplayName
    if (-not $role) {
        $templateId = $RoleTemplateMap[$DisplayName]
        if (-not $templateId) { throw "Unknown role: $DisplayName" }
        Write-Host "Activating directory role: $DisplayName" -ForegroundColor Cyan
        New-MgDirectoryRole -RoleTemplateId $templateId | Out-Null
        $role = Get-MgDirectoryRole | Where-Object DisplayName -eq $DisplayName
    }
    return $role
}

<#
.SYNOPSIS
    Assigns a user to a directory role.

.DESCRIPTION
    Assigns the specified user to the given directory role for administrative privileges.
    Used to grant administrative permissions to lab users for training scenarios.

.PARAMETER UserId
    The Object ID of the user to assign

.PARAMETER RoleName
    The name of the directory role to assign
#>
function Set-UserDirectoryRoleAssignment {
    param(
        [Parameter(Mandatory)] $User,
        [Parameter(Mandatory)] [string]$RoleDisplayName
    )
    
    # Get the user ID, handling different object types
    $userId = $null
    if ($User.Id) {
        $userId = $User.Id
    } elseif ($User.ObjectId) {
        $userId = $User.ObjectId
    } elseif ($User -is [string]) {
        $userId = $User
    } else {
        Write-Warning "Unable to determine user ID from User object. Available properties: $($User | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name -Join ', ')"
        throw "Cannot extract user ID from provided User object"
    }
    
    Write-Verbose "Assigning role '$RoleDisplayName' to user ID: $userId"
    
    $role = Enable-DirectoryRole -DisplayName $RoleDisplayName
    $existing = @()
    try {
        $existing = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction Stop
    } catch {
        Write-Verbose "Could not retrieve existing role members: $($_.Exception.Message)"
    }
    
    # Check if user already has the role
    $userAlreadyHasRole = $false
    if ($existing) {
        # Handle both single objects and collections
        $members = @($existing)  # Force into array to handle single objects
        if ($members.Length -gt 0) {
            foreach ($member in $members) {
                $memberId = $null
                if ($member.Id) {
                    $memberId = $member.Id
                } elseif ($member.ObjectId) {
                    $memberId = $member.ObjectId
                } elseif ($member -is [string]) {
                    $memberId = $member
                }
                
                if ($memberId -eq $userId) {
                    $userAlreadyHasRole = $true
                    break
                }
            }
        }
    }
    
    if ($userAlreadyHasRole) {
        Write-Verbose "User already has role '$RoleDisplayName'"
        return
    }
    
    try {
        $ref = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$userId"
        }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -BodyParameter $ref | Out-Null
        Write-Verbose "Successfully assigned role '$RoleDisplayName' to user"
    } catch {
        Write-Error "Failed to assign role '$RoleDisplayName' to user: $($_.Exception.Message)"
        throw
    }
}

<#
.SYNOPSIS
    Creates a new security group in Azure AD.

.DESCRIPTION
    Creates a security group with the specified name and adds members if provided.
    Used for organizing users and managing permissions in the lab environment.

.PARAMETER GroupName
    The name of the group to create

.PARAMETER Description
    Optional description for the group

.PARAMETER Members
    Optional array of user Object IDs to add as members

.OUTPUTS
    Microsoft.Graph.PowerShell.Models.MicrosoftGraphGroup
    The created group object
#>
function New-LabSecurityGroup {
    param(
        [Parameter(Mandatory)] [string]$DisplayName
    )
    # Try to find existing group by display name (first match)
    $escaped = $DisplayName.Replace("'", "''")
    $existing = Get-MgGroup -Filter "displayName eq '$escaped'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue
    if ($existing) {
        if ($existing -is [array]) { $existing = $existing[0] }
        return New-Object PSObject -Property @{ Group = $existing; Created = $false }
    }
    
    $mailNick = ($DisplayName -replace '[^a-z0-9]', '').ToLower()
    if ([string]::IsNullOrWhiteSpace($mailNick)) { $mailNick = "grp$([guid]::NewGuid().ToString('N').Substring(0,8))" }
    
    # Check if this is a license group (starts with 'lic') - these should be Microsoft 365 groups
    if ($DisplayName -like "lic-*") {
        Write-Host "Creating Microsoft 365 group for license group: $DisplayName" -ForegroundColor Cyan
        $group = New-MgGroup -DisplayName $DisplayName -MailEnabled:$true -SecurityEnabled:$true -MailNickname $mailNick -GroupTypes @("Unified")
    } else {
        # Regular security group
        $group = New-MgGroup -DisplayName $DisplayName -MailEnabled:$false -SecurityEnabled:$true -MailNickname $mailNick -GroupTypes @()
    }
    
    return New-Object PSObject -Property @{ Group = $group; Created = $true }
}

<#
.SYNOPSIS
    Ensures Azure PowerShell modules are installed and user is logged in to Azure.

.DESCRIPTION
    Checks if required Azure PowerShell modules are installed and installs them if missing.
    Also ensures the user is authenticated to Azure. This function improves performance
    by avoiding reinstallation of already available modules.

.NOTES
    This function requires sufficient permissions to install modules and authenticate to Azure.
#>
function Ensure-AzModulesAndLogin {
    [CmdletBinding()]
    param()

    try {
        # Required Azure PowerShell modules
        $requiredAzModules = @(
            'Az.Accounts',
            'Az.Resources', 
            'Az.KeyVault',
            'Az.Automation',
            'Az.OperationalInsights',
            'Az.Network',
            'Az.Compute',
            'Az.ManagedServiceIdentity',
            'Az.Storage'
        )

        # Check and install missing modules
        $missingModules = @()
        foreach ($module in $requiredAzModules) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                $missingModules += $module
            }
        }

        if ($missingModules.Count -gt 0) {
            Write-Host "Installing missing Azure PowerShell modules: $($missingModules -join ', ')" -ForegroundColor Cyan
            foreach ($module in $missingModules) {
                Write-Host "Installing $module..." -ForegroundColor Gray
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            }
        } else {
            Write-Host "All required Azure PowerShell modules are already installed." -ForegroundColor Green
        }

        # Import modules if not already imported
        foreach ($module in $requiredAzModules) {
            if (-not (Get-Module -Name $module)) {
                Import-Module $module -Force
            }
        }

        # Check Azure authentication
        $azContext = Get-AzContext
        if (-not $azContext) {
            Write-Host "Connecting to Azure..." -ForegroundColor Cyan
            Connect-AzAccount | Out-Null
            $azContext = Get-AzContext
        } else {
            Write-Host "Already connected to Azure as: $($azContext.Account.Id)" -ForegroundColor Green
        }

        # Register required resource providers
        $providers = @(
            "Microsoft.KeyVault",
            "Microsoft.Automation", 
            "Microsoft.OperationalInsights",
            "Microsoft.Insights",
            "Microsoft.Network",
            "Microsoft.Compute",
            "Microsoft.ManagedIdentity",
            "Microsoft.Storage"
        )

        Write-Host "Ensuring resource providers are registered..." -ForegroundColor Cyan
        foreach ($provider in $providers) {
            $registration = Get-AzResourceProvider -ProviderNamespace $provider
            if ($registration.RegistrationState -ne "Registered") {
                Write-Host "Registering provider: $provider" -ForegroundColor Gray
                Register-AzResourceProvider -ProviderNamespace $provider | Out-Null
            }
        }

        $providerFeatures = @(
            @{ namespace = "Microsoft.Compute"; feature = "UseStandardSecurityType" }
        )

        Write-Host "Ensuring provider features are registered..." -ForegroundColor Cyan
        foreach ($feature in $providerFeatures) {
            $registration = Get-AzProviderFeature -ProviderNamespace $feature.namespace -FeatureName $feature.feature
            if ($registration.RegistrationState -ne "Registered") {
                Write-Host "Registering provider feature: $($feature.namespace).$($feature.feature)" -ForegroundColor Gray
                Register-AzProviderFeature -ProviderNamespace $feature.namespace -FeatureName $feature.feature | Out-Null
            }
        }

        Write-Verbose "Azure modules and authentication ready"
    }
    catch {
        Write-Error "Failed to ensure Azure modules and login: $($_.Exception.Message)"
        throw
    }
}

<#
.SYNOPSIS
    Ensures Azure PowerShell modules are installed and authenticates to Azure.

.DESCRIPTION
    Checks for required Azure PowerShell modules, installs them if missing,
    and establishes an authenticated connection to Azure for resource management.

.NOTES
    This function installs modules in CurrentUser scope and will prompt for
    Azure authentication if not already signed in.
#>
function Connect-ToAzureServices {
    Import-Module Az.Accounts
    Import-Module Az.Resources
    Import-Module Az.KeyVault
    Import-Module Az.OperationalInsights
    Import-Module Az.Automation
    Import-Module Az.Network
    Import-Module Az.Compute
    Import-Module Az.ManagedServiceIdentity
    Import-Module Az.Storage
    if (-not (Get-AzContext)) {
        Write-Host "Connecting to Azure..." -ForegroundColor Cyan
        Connect-AzAccount | Out-Null
    }
    foreach ($provider in @(
        "Microsoft.KeyVault",
        "Microsoft.Automation",
        "Microsoft.OperationalInsights",
        "Microsoft.Insights",
        "Microsoft.Network",
        "Microsoft.Compute",
        "Microsoft.ManagedIdentity",
        "Microsoft.Storage"           # New
    )) {
        $reg = Get-AzResourceProvider -ProviderNamespace $provider
        if ($reg.RegistrationState -ne "Registered") {
            Write-Host "Registering resource provider: $provider" -ForegroundColor DarkCyan
            Register-AzResourceProvider -ProviderNamespace $provider | Out-Null
        }
    }
}

<#
.SYNOPSIS
    Tests system requirements and prerequisites for deployment.

.DESCRIPTION
    Verifies that all required dependencies and tools are available
    before starting the lab environment deployment.

.NOTES
    This function checks for PowerShell modules and other prerequisites.
#>
function Test-DeploymentPrerequisites {
    [CmdletBinding()]
    param()
    
    Write-Host "Running deployment prerequisite checks..." -ForegroundColor Cyan
    
    $missing = @()
    $warnings = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        $warnings += "PowerShell 7+ is recommended (current: $($PSVersionTable.PSVersion))"
    }
    
    # Check Microsoft Graph modules (specific modules instead of monolithic package)
    $graphModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications", 
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Identity.Governance"
    )
    
    foreach ($module in $graphModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) { 
            $missing += "PowerShell module: $module" 
        }
    }
    
    # Check Azure PowerShell modules
    $azModules = @(
        "Az.Accounts","Az.Resources","Az.KeyVault","Az.OperationalInsights",
        "Az.Automation","Az.Network","Az.Compute","Az.ManagedServiceIdentity","Az.Storage"
    )
    
    foreach ($module in $azModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) { 
            $missing += "PowerShell module: $module" 
        }
    }
    
    # Check current connections (optional checks)
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azContext) {
        $warnings += "Not currently connected to Azure (will prompt for authentication)"
    } else {
        Write-Host "✓ Connected to Azure as: $($azContext.Account.Id)" -ForegroundColor Green
    }
    
    $mgContext = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $mgContext) {
        $warnings += "Not currently connected to Microsoft Graph (will prompt for authentication)"
    } else {
        Write-Host "✓ Connected to Microsoft Graph as: $($mgContext.Account)" -ForegroundColor Green
    }
    
    # Report results
    if ($missing.Count -gt 0) {
        Write-Host "❌ Preflight checks failed. Missing prerequisites:" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
        Write-Host ""
        Write-Host "Please run the module installation commands from the README.md file." -ForegroundColor Yellow
        throw "Missing prerequisites."
    }
    
    if ($warnings.Count -gt 0) {
        Write-Host "⚠️  Warnings:" -ForegroundColor Yellow
        $warnings | ForEach-Object { Write-Host "   - $_" -ForegroundColor Yellow }
        Write-Host ""
    }
    
    Write-Host "✅ Preflight checks passed!" -ForegroundColor Green
}

<#
.SYNOPSIS
    Creates enterprise applications for the lab environment.

.DESCRIPTION
    Creates various Azure AD enterprise applications with intentionally excessive
    permissions for security training purposes. These applications demonstrate
    common security misconfigurations.

.PARAMETER Domain
    The tenant domain name for application configuration

.OUTPUTS
    System.Collections.Hashtable
    A hashtable containing the created applications and their details
#>
function New-LabEnterpriseApplications {
    # Create/ensure "Office.Read" app + SP + secret
    $apps = @()
    $officeApp = Get-MgApplication -Filter "displayName eq 'Office.Read'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
    $officeCreated = $false
    if (-not $officeApp) {
        $officeApp = New-MgApplication -DisplayName "Office.Read" -SignInAudience "AzureADMultipleOrgs" -Web @{ RedirectUris = @("http://localhost:5000/getAToken") }
        $officeCreated = $true
    }
    $officeSp = Get-MgServicePrincipal -Filter "appId eq '$($officeApp.AppId)'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $officeSp) { $officeSp = New-MgServicePrincipal -AppId $officeApp.AppId }
    $officeSecretValue = $null
    if ($officeCreated) {
        try {
            # Create password credential (DisplayName parameter may vary by module version)
            $passwordCredential = @{
                displayName = "DefaultSecret"
            }
            $secret = Add-MgApplicationPassword -ApplicationId $officeApp.Id -PasswordCredential $passwordCredential
            $officeSecretValue = $secret.SecretText
        } catch {
            # Fallback method if the above fails
            try {
                $secret = Add-MgApplicationPassword -ApplicationId $officeApp.Id
                $officeSecretValue = $secret.SecretText
            } catch {
                Write-Warning "Failed to create client secret for Office.Read app: $($_.Exception.Message)"
                $officeSecretValue = $null
            }
        }
    }
    $officeAppObj = New-Object PSObject -Property @{
        DisplayName = "Office.Read"
        AppId       = $officeApp.AppId
        Secret      = $officeSecretValue
        TenantId    = (Get-MgContext).TenantId
        CreatedNow  = $officeCreated
    }
    $apps += $officeAppObj

    # Create/ensure "Maintain User" app + SP + assign 'User Administrator' directory role
    $maintainApp = Get-MgApplication -Filter "displayName eq 'Maintain User'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
    $maintainCreated = $false
    if (-not $maintainApp) {
        $maintainApp = New-MgApplication -DisplayName "Maintain User" -SignInAudience "AzureADMultipleOrgs"
        $maintainCreated = $true
    }
    $maintainSp = Get-MgServicePrincipal -Filter "appId eq '$($maintainApp.AppId)'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $maintainSp) { $maintainSp = New-MgServicePrincipal -AppId $maintainApp.AppId }

    $userAdminRole = Enable-DirectoryRole -DisplayName "User Administrator"
    
    # Check if SP is already assigned to the directory role
    $maintainAssigned = $false
    $alreadyMember = $false
    
    try {
        $existingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $userAdminRole.Id -ErrorAction Stop
        $members = @($existingMembers)  # Force into array
        
        Write-Host "  Checking existing User Administrator role members ($($members.Length) found)..." -ForegroundColor Gray
        
        if ($members.Length -gt 0) {
            foreach ($member in $members) {
                $memberId = $null
                
                # Try multiple ways to get the member ID
                if ($member.Id) {
                    $memberId = $member.Id
                } elseif ($member.ObjectId) {
                    $memberId = $member.ObjectId
                } elseif ($member.AdditionalProperties -and $member.AdditionalProperties.id) {
                    $memberId = $member.AdditionalProperties.id
                } elseif ($member.AdditionalProperties -and $member.AdditionalProperties.objectId) {
                    $memberId = $member.AdditionalProperties.objectId
                } elseif ($member -is [string]) {
                    $memberId = $member
                }
                
                Write-Host "    Checking member: $memberId" -ForegroundColor DarkGray
                
                if ($memberId -and ($memberId -eq $maintainSp.Id)) {
                    $alreadyMember = $true
                    $maintainAssigned = $true
                    Write-Host "  ✓ Maintain User app already assigned to User Administrator role" -ForegroundColor Yellow
                    break
                }
            }
        }
        
        if (-not $alreadyMember) {
            Write-Host "  Maintain User app not found in existing role members - proceeding with assignment" -ForegroundColor Gray
        }
    } catch {
        Write-Warning "Could not retrieve existing User Administrator role members: $($_.Exception.Message)"
        Write-Host "  Proceeding with assignment attempt..." -ForegroundColor Gray
    }
    
    # Only assign if not already a member
    if (-not $alreadyMember) {
        try {
            Write-Host "  Assigning Maintain User app to User Administrator role..." -ForegroundColor Gray
            
            # Double-check with a fresh query just before assignment to catch timing issues
            $recentMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $userAdminRole.Id -ErrorAction SilentlyContinue
            $doubleCheckMember = $recentMembers | Where-Object { 
                $_.Id -eq $maintainSp.Id -or 
                $_.ObjectId -eq $maintainSp.Id -or 
                ($_.AdditionalProperties -and ($_.AdditionalProperties.id -eq $maintainSp.Id -or $_.AdditionalProperties.objectId -eq $maintainSp.Id))
            }
            
            if ($doubleCheckMember) {
                Write-Host "  ✓ Maintain User app already assigned to User Administrator role (found in double-check)" -ForegroundColor Yellow
                $maintainAssigned = $true
            } else {
                New-MgDirectoryRoleMemberByRef -DirectoryRoleId $userAdminRole.Id -BodyParameter @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($maintainSp.Id)" } | Out-Null
                $maintainAssigned = $true
                Write-Host "  ✓ Assigned Maintain User app to User Administrator role" -ForegroundColor DarkGreen
            }
        } catch {
            if ($_.Exception.Message -like "*One or more added object references already exist*" -or $_.Exception.Message -like "*already exist*") {
                $maintainAssigned = $true
                Write-Host "  ✓ Maintain User app already assigned to User Administrator role (detected during assignment)" -ForegroundColor Yellow
            } else {
                Write-Warning "Failed to assign Maintain User app to User Administrator role: $($_.Exception.Message)"
                Write-Host "  This may not affect the lab functionality - continuing..." -ForegroundColor Yellow
                $maintainAssigned = $false
            }
        }
    }
    $maintainUserAppObj = New-Object PSObject -Property @{
        DisplayName = "Maintain User"
        AppId       = $maintainApp.AppId
        Secret      = $null
        TenantId    = (Get-MgContext).TenantId
        CreatedNow  = $maintainCreated
    }
    $apps += $maintainUserAppObj

    # --- New helper to grant Graph application permissions (app roles) to a service principal ---
    <#
    .SYNOPSIS
        Grants Microsoft Graph API permissions to an application.

    .DESCRIPTION
        Assigns the specified Microsoft Graph permissions to an enterprise application.
        This function handles the service principal permission grants for API access.

    .PARAMETER ServicePrincipalId
        The Object ID of the service principal

    .PARAMETER Permissions
        Array of permission names to grant
    #>
    function Grant-GraphApplicationPermissions {
        param(
            [Parameter(Mandatory)] [string]$PrincipalServicePrincipalId,
            [Parameter(Mandatory)] [string[]]$RoleValues
        )
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ConsistencyLevel eventual | Select-Object -First 1
        if (-not $graphSp) { throw "Microsoft Graph service principal not found in tenant." }

        $existing = @()
        try { $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalServicePrincipalId } catch {}

        foreach ($value in $RoleValues) {
            $appRole = ($graphSp.AppRoles | Where-Object { $_.IsEnabled -and $_.Value -eq $value }) | Select-Object -First 1
            if (-not $appRole) { Write-Warning "Graph app role '$value' not found. Skipping."; continue }
            $already = $existing | Where-Object { $_.AppRoleId -eq $appRole.Id -and $_.ResourceId -eq $graphSp.Id }
            if ($already) { 
                Write-Verbose "App role '$value' already assigned to service principal"
                continue 
            }
            
            try {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalServicePrincipalId `
                    -PrincipalId $PrincipalServicePrincipalId `
                    -ResourceId $graphSp.Id `
                    -AppRoleId $appRole.Id -ErrorAction Stop | Out-Null
                Write-Host "  ✓ Assigned Graph API role: $value" -ForegroundColor DarkGreen
            } catch {
                if ($_.Exception.Message -like "*Insufficient privileges*" -or $_.Exception.Message -like "*Authorization_RequestDenied*") {
                    Write-Host "  ⚠️  Insufficient privileges to assign Graph API role '$value'" -ForegroundColor Yellow
                    Write-Host "     This requires Application Administrator or Global Administrator privileges." -ForegroundColor Gray
                    Write-Host "     You may need to manually grant these permissions in the Azure portal." -ForegroundColor Gray
                } else {
                    Write-Warning "  ❌ Failed to assign Graph API role '$value': $($_.Exception.Message)"
                }
            }
        }
    }

    # --- New: Create/ensure "evil automation account" with long-lived secret and Graph app permissions ---
    $evilApp = Get-MgApplication -Filter "displayName eq 'evil automation account'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
    $evilCreated = $false
    if (-not $evilApp) {
        $evilApp = New-MgApplication -DisplayName "evil automation account" -SignInAudience "AzureADMyOrg"
        $evilCreated = $true
    }
    $evilSp = Get-MgServicePrincipal -Filter "appId eq '$($evilApp.AppId)'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $evilSp) { $evilSp = New-MgServicePrincipal -AppId $evilApp.AppId }

    # Add long-lived secret (5 years) on first creation
    $evilSecretValue = $null
    if ($evilCreated) {
        $cred = @{
            displayName = "LongLived"
            endDateTime = (Get-Date).AddYears(5)
        }
        $secret = Add-MgApplicationPassword -ApplicationId $evilApp.Id -PasswordCredential $cred
        $evilSecretValue = $secret.SecretText
    }

    # Assign required Graph application permissions
    Grant-GraphApplicationPermissions -PrincipalServicePrincipalId $evilSp.Id -RoleValues @(
        "DeviceManagementApps.ReadWrite.All",
        "DeviceManagementConfiguration.ReadWrite.All",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "DeviceManagementServiceConfig.ReadWrite.All",
        "Directory.ReadWrite.All",
        "User.ReadWrite.All"
    )

    $evilAppObj = New-Object PSObject -Property @{
        DisplayName = "evil automation account"
        AppId       = $evilApp.AppId
        Secret      = $evilSecretValue
        TenantId    = (Get-MgContext).TenantId
        CreatedNow  = $evilCreated
    }
    $apps += $evilAppObj

    return $apps
}

function Deploy-Infrastructure {
    param(
        [Parameter(Mandatory)] [string]$ResourceGroupName,
        [Parameter(Mandatory)] [string]$AzureLocation,
        [Parameter(Mandatory)] [string]$KeyVaultName,
        [Parameter(Mandatory)] [string]$AutomationAccountName,
        [Parameter(Mandatory)] [string]$LogAnalyticsWorkspaceName,
        # --- New ---
        [Parameter(Mandatory)] [string]$StorageAccountName
    )
    Ensure-AzModulesAndLogin

    if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
        New-AzResourceGroup -Name $ResourceGroupName -Location $AzureLocation | Out-Null
    }

    # Make resource names unique by adding a timestamp suffix
    $timestamp = Get-Date -Format "MMddHHmm"
    $uniqueKeyVaultName = "$KeyVaultName$timestamp"
    $uniqueStorageAccountName = "$StorageAccountName$timestamp"
    $uniqueAutomationAccountName = "$AutomationAccountName$timestamp"
    $uniqueLogAnalyticsWorkspaceName = "$LogAnalyticsWorkspaceName$timestamp"
    
    # Validate name lengths and adjust if needed
    if ($uniqueKeyVaultName.Length -gt 24) {
        $uniqueKeyVaultName = $KeyVaultName.Substring(0, [Math]::Min(16, $KeyVaultName.Length)) + $timestamp
    }
    if ($uniqueStorageAccountName.Length -gt 24) {
        $uniqueStorageAccountName = $StorageAccountName.Substring(0, [Math]::Min(16, $StorageAccountName.Length)) + $timestamp
    }
    if ($uniqueAutomationAccountName.Length -gt 50) {
        $uniqueAutomationAccountName = $AutomationAccountName.Substring(0, [Math]::Min(42, $AutomationAccountName.Length)) + $timestamp
    }
    if ($uniqueLogAnalyticsWorkspaceName.Length -gt 63) {
        $uniqueLogAnalyticsWorkspaceName = $LogAnalyticsWorkspaceName.Substring(0, [Math]::Min(55, $LogAnalyticsWorkspaceName.Length)) + $timestamp
    }
    
    Write-Host "Using unique resource names:" -ForegroundColor Cyan
    Write-Host "  Key Vault: $uniqueKeyVaultName" -ForegroundColor Gray
    Write-Host "  Storage Account: $uniqueStorageAccountName" -ForegroundColor Gray
    Write-Host "  Automation Account: $uniqueAutomationAccountName" -ForegroundColor Gray
    Write-Host "  Log Analytics: $uniqueLogAnalyticsWorkspaceName" -ForegroundColor Gray

    $templateFile = Join-Path $PSScriptRoot "infrastructure-arm.json"

    # Ensure automation groups exist and collect IDs for ARM parameters
    $autoOwner = (New-LabSecurityGroup -DisplayName 'perm-xintraautomation-owner').Group.Id
    $autoContributor = (New-LabSecurityGroup -DisplayName 'perm-xintraautomation-contributer').Group.Id

    Write-Host "Creating infrastructure resources individually for better reliability..." -ForegroundColor Cyan
    
    # Create Key Vault
    try {
        $existingKv = Get-AzKeyVault -VaultName $uniqueKeyVaultName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $existingKv) {
            $kvParams = @{
                VaultName = $uniqueKeyVaultName
                ResourceGroupName = $ResourceGroupName
                Location = $AzureLocation
                EnabledForDeployment = $true
                EnabledForTemplateDeployment = $true
                EnabledForDiskEncryption = $true
                Sku = "Standard"
            }
            New-AzKeyVault @kvParams | Out-Null
            Write-Host "✓ Key Vault '$uniqueKeyVaultName' created successfully" -ForegroundColor Green
            
            # Add access policy for current user to manage secrets
            try {
                $currentUser = Get-AzContext
                if ($currentUser -and $currentUser.Account) {
                    # Get the current user's object ID
                    $userObjectId = $null
                    if ($currentUser.Account.Type -eq "User") {
                        # For user accounts, try to get the object ID from Microsoft Graph
                        try {
                            $mgUser = Get-MgUser -UserId $currentUser.Account.Id -ErrorAction SilentlyContinue
                            if ($mgUser) {
                                $userObjectId = $mgUser.Id
                            }
                        } catch {
                            Write-Verbose "Could not get user object ID from Microsoft Graph"
                        }
                    }
                    
                    if ($userObjectId) {
                        try {
                            Set-AzKeyVaultAccessPolicy -VaultName $uniqueKeyVaultName -ObjectId $userObjectId `
                                -PermissionsToSecrets Get,List,Set,Delete,Backup,Restore,Recover,Purge `
                                -PermissionsToKeys Get,List,Create,Delete,Import,Backup,Restore,Recover,Purge `
                                -PermissionsToCertificates Get,List,Create,Delete,Import,Backup,Restore,Recover,Purge | Out-Null
                            Write-Host "✓ Added access policy for current user" -ForegroundColor Green
                        } catch {
                            # Fallback: Try RBAC approach
                            try {
                                $kvResourceId = "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$uniqueKeyVaultName"
                                New-AzRoleAssignment -ObjectId $userObjectId -RoleDefinitionName "Key Vault Administrator" -Scope $kvResourceId | Out-Null
                                Write-Host "✓ Added RBAC role for current user (fallback)" -ForegroundColor Green
                            } catch {
                                Write-Warning "Failed to add Key Vault permissions: $($_.Exception.Message)"
                            }
                        }
                    } else {
                        Write-Host "⚠️  Could not determine current user object ID for Key Vault access policy" -ForegroundColor Yellow
                        Write-Host "   You may need to manually grant yourself Key Vault permissions" -ForegroundColor Gray
                    }
                }
            } catch {
                Write-Warning "Failed to add access policy for current user: $($_.Exception.Message)"
                Write-Host "  You may need to manually grant yourself Key Vault permissions" -ForegroundColor Yellow
            }
        } else {
            Write-Host "✓ Key Vault '$uniqueKeyVaultName' already exists" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to create Key Vault: $($_.Exception.Message)"
    }
    
    # Create Automation Account
    try {
        $existingAa = Get-AzAutomationAccount -Name $uniqueAutomationAccountName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $existingAa) {
            # Try without -Plan parameter first (it might not be supported in all regions/versions)
            try {
                New-AzAutomationAccount -Name $uniqueAutomationAccountName -ResourceGroupName $ResourceGroupName -Location $AzureLocation | Out-Null
                Write-Host "✓ Automation Account '$uniqueAutomationAccountName' created successfully" -ForegroundColor Green
            } catch {
                # Fallback: try with explicit plan
                try {
                    New-AzAutomationAccount -Name $uniqueAutomationAccountName -ResourceGroupName $ResourceGroupName -Location $AzureLocation -Plan Basic | Out-Null
                    Write-Host "✓ Automation Account '$uniqueAutomationAccountName' created successfully (with Basic plan)" -ForegroundColor Green
                } catch {
                    throw $_.Exception
                }
            }
        } else {
            Write-Host "✓ Automation Account '$uniqueAutomationAccountName' already exists" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to create Automation Account: $($_.Exception.Message)"
        Write-Host "  Continuing without Automation Account..." -ForegroundColor Yellow
    }
    
    # Create Log Analytics Workspace
    try {
        $existingLa = Get-AzOperationalInsightsWorkspace -Name $uniqueLogAnalyticsWorkspaceName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $existingLa) {
            New-AzOperationalInsightsWorkspace -Name $uniqueLogAnalyticsWorkspaceName -ResourceGroupName $ResourceGroupName -Location $AzureLocation -Sku PerGB2018 | Out-Null
            Write-Host "✓ Log Analytics Workspace '$uniqueLogAnalyticsWorkspaceName' created successfully" -ForegroundColor Green
        } else {
            Write-Host "✓ Log Analytics Workspace '$uniqueLogAnalyticsWorkspaceName' already exists" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to create Log Analytics Workspace: $($_.Exception.Message)"
    }
    
    # Create diagnostic settings for Key Vault (optional)
    $kvForDiag = Get-AzKeyVault -VaultName $uniqueKeyVaultName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    $laForDiag = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $uniqueLogAnalyticsWorkspaceName -ErrorAction SilentlyContinue
    
    if ($kvForDiag -and $laForDiag) {
        Write-Host "✓ Key Vault and Log Analytics available for diagnostic settings" -ForegroundColor Gray
        # Diagnostic settings can be configured manually or via Azure CLI if needed
        # This is optional for lab functionality
    }
    
    # Update global variables to use the unique names
    $script:ActualKeyVaultName = $uniqueKeyVaultName
    $script:ActualStorageAccountName = $uniqueStorageAccountName
    $script:ActualAutomationAccountName = $uniqueAutomationAccountName
    $script:ActualLogAnalyticsWorkspaceName = $uniqueLogAnalyticsWorkspaceName
    
    # Apply RBAC assignments for automation account groups (since we're not using ARM template)
    $aa = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $uniqueAutomationAccountName -ErrorAction SilentlyContinue
    if ($aa) {
        # Construct the resource ID manually since the object may not have an Id property
        $automationAccountResourceId = "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$uniqueAutomationAccountName"
        
        try {
            New-AzRoleAssignment -ObjectId $autoOwner -RoleDefinitionName "Owner" -Scope $automationAccountResourceId -ErrorAction Stop | Out-Null
            Write-Host "✓ Assigned Owner role to automation owner group" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -notmatch 'already exists') {
                Write-Warning "Failed to assign Owner role to automation owner group: $($_.Exception.Message)"
            }
        }
        
        try {
            New-AzRoleAssignment -ObjectId $autoContributor -RoleDefinitionName "Contributor" -Scope $automationAccountResourceId -ErrorAction Stop | Out-Null
            Write-Host "✓ Assigned Contributor role to automation contributor group" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -notmatch 'already exists') {
                Write-Warning "Failed to assign Contributor role to automation contributor group: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Warning "Automation Account not found, skipping RBAC assignments"
    }

    # Fetch resources using the unique names
    $kv = Get-AzKeyVault -VaultName $uniqueKeyVaultName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    $la = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $uniqueLogAnalyticsWorkspaceName -ErrorAction SilentlyContinue
    $aa = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $uniqueAutomationAccountName -ErrorAction SilentlyContinue

    # Create Storage Account with intentional misconfigurations
    $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $uniqueStorageAccountName -ErrorAction SilentlyContinue
    if (-not $sa) {
        Write-Host "Creating misconfigured Storage Account '$uniqueStorageAccountName'..." -ForegroundColor Cyan
        try {
            # Create storage account with basic parameters
            $sa = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $uniqueStorageAccountName `
                -Location $AzureLocation -SkuName Standard_LRS -Kind StorageV2
            
            Write-Host "✓ Storage Account '$uniqueStorageAccountName' created successfully" -ForegroundColor Green
            
            # Apply network and access misconfigurations
            try {
                # Configure network access rules (allow all)
                Update-AzStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName -Name $uniqueStorageAccountName `
                    -DefaultAction Allow -Bypass AzureServices | Out-Null
                
                # Try to enable blob public access if the parameter is available
                try {
                    Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $uniqueStorageAccountName `
                        -AllowBlobPublicAccess $true | Out-Null
                    Write-Host "✓ Enabled blob public access (vulnerability)" -ForegroundColor Yellow
                } catch {
                    Write-Verbose "Blob public access parameter not available in this version"
                }
                
                Write-Host "✓ Storage Account configured with available misconfigurations" -ForegroundColor Green
                Write-Host "  Note: Additional security misconfigurations can be applied via Azure portal" -ForegroundColor Gray
            } catch {
                Write-Warning "Failed to apply some storage misconfigurations: $($_.Exception.Message)"
            }
        } catch {
            Write-Warning "Failed to create Storage Account: $($_.Exception.Message)"
            Write-Host "Continuing without Storage Account..." -ForegroundColor Yellow
            $sa = $null
        }
    } else {
        Write-Host "✓ Storage Account '$uniqueStorageAccountName' already exists" -ForegroundColor Yellow
    }

    # Prepare context, make public container, generate long-lived SAS, and leak access key into the account
    if ($sa) {
        try {
            $keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $uniqueStorageAccountName
            $primaryKey = $keys[0].Value
            $ctx = New-AzStorageContext -StorageAccountName $uniqueStorageAccountName -StorageAccountKey $primaryKey

            # 1) Create public container with anonymous access (container-level)
            try {
                $container = New-AzStorageContainer -Name "public" -Context $ctx -Permission Container -ErrorAction Stop
                Write-Host "✓ Created public container with anonymous access" -ForegroundColor Yellow
            } catch {
                if ($_.Exception.Message -like "*already exists*") {
                    Write-Host "✓ Public container already exists" -ForegroundColor Yellow
                    $container = Get-AzStorageContainer -Name "public" -Context $ctx
                } else {
                    Write-Warning "Failed to create public container: $($_.Exception.Message)"
                    $container = $null
                }
            }

            # 2) Generate overly generous SAS token (all services/types, racwdl, 10 years, HTTP allowed)
            $sasExpiry = (Get-Date).AddYears(10)
            $accountSas = New-AzStorageAccountSASToken -Context $ctx `
                -Service Blob,File,Queue,Table -ResourceType Service,Container,Object `
                -Permission "racwdl" -ExpiryTime $sasExpiry -Protocol HttpsOrHttp
            Write-Host "Account SAS (10y, racwdl): $accountSas" -ForegroundColor DarkYellow
            
            # Store SAS details for export
            $global:StorageAccountSas = @{
                StorageAccountName = $uniqueStorageAccountName
                SasToken = $accountSas
                Expiry = $sasExpiry
                Permissions = "racwdl"
                Services = "Blob,File,Queue,Table"
                ResourceTypes = "Service,Container,Object"
            }

            # 3) Leak access key by uploading it into the same storage account (only if container exists)
            if ($container) {
                try {
                    $tmpKeyFile = Join-Path $env:TEMP "access-key.txt"
                    Set-Content -Path $tmpKeyFile -Value $primaryKey -NoNewline
                    Set-AzStorageBlobContent -File $tmpKeyFile -Container "public" -Blob "access-key.txt" -Context $ctx -Force | Out-Null
                    Remove-Item $tmpKeyFile -Force
                    Write-Host "✓ Leaked access key to public container (vulnerability)" -ForegroundColor Yellow
                } catch {
                    Write-Warning "Failed to upload access key to container: $($_.Exception.Message)"
                    # Clean up temp file if it exists
                    if (Test-Path $tmpKeyFile) { Remove-Item $tmpKeyFile -Force }
                }
            }
            Write-Host "✓ Storage Account configured with intentional vulnerabilities" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to configure Storage Account vulnerabilities: $($_.Exception.Message)"
        }
    }

    # RBAC mappings and assignments
    $rbacTargets = @()
    
    # Add Key Vault RBAC targets if Key Vault exists
    if ($kv) {
        $rbacTargets += @(
            @{ GroupName='perm-xintrakey-reader';        Role='Key Vault Secrets User';                  Scope=$kv.ResourceId },
            @{ GroupName='perm-xintrakey-contributer';   Role='Key Vault Contributor';                   Scope=$kv.ResourceId },
            @{ GroupName='perm-xintrakey-owner';         Role='Key Vault Administrator';                 Scope=$kv.ResourceId },
            # Legacy groups
            @{ GroupName='KeyVault-Secrets-Reader';      Role='Key Vault Secrets User';                  Scope=$kv.ResourceId },
            @{ GroupName='KeyVault-AccessPolicy-Admin';  Role='Key Vault Administrator';                 Scope=$kv.ResourceId }
        )
    }
    
    # Add Automation Account RBAC targets if it exists
    if ($aa) {
        $automationAccountResourceId = "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$uniqueAutomationAccountName"
        $rbacTargets += @(
            @{ GroupName='perm-xintraautomation-reader'; Role='Reader'; Scope=$automationAccountResourceId }
        )
    }
    
    # Add Log Analytics RBAC targets if it exists
    if ($la) {
        $rbacTargets += @(
            @{ GroupName='perm-xintralog-reader';        Role='Log Analytics Reader';                    Scope=$la.ResourceId },
            @{ GroupName='perm-xintralog-contributer';   Role='Log Analytics Contributor';               Scope=$la.ResourceId },
            @{ GroupName='perm-xintralog-owner';         Role='Owner';                                   Scope=$la.ResourceId }
        )
    }
    
    # Add Storage Account RBAC targets if it exists
    if ($sa) {
        $storageAccountResourceId = "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$uniqueStorageAccountName"
        $rbacTargets += @(
            @{ GroupName='perm-xintrastore-reader';      Role='Reader';                                  Scope=$storageAccountResourceId },
            @{ GroupName='perm-xintrastore-contributer'; Role='Contributor';                             Scope=$storageAccountResourceId },
            @{ GroupName='perm-xintrastore-owner';       Role='Owner';                                   Scope=$storageAccountResourceId }
        )
    }

    foreach ($t in $rbacTargets) {
        if ($t.Scope) {  # Only process if scope is valid
            $gid = (New-LabSecurityGroup -DisplayName $t.GroupName).Group.Id
            try {
                New-AzRoleAssignment -ObjectId $gid -RoleDefinitionName $t.Role -Scope $t.Scope -ErrorAction Stop | Out-Null
                Write-Host "✓ Assigned $($t.Role) to $($t.GroupName)" -ForegroundColor DarkGreen
            } catch {
                if ($_.Exception.Message -notmatch 'already exists') {
                    Write-Warning "RBAC assignment failed for $($t.GroupName) ($($t.Role)): $($_.Exception.Message)"
                } else {
                    Write-Host "✓ $($t.GroupName) already has $($t.Role) role" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Warning "Skipping RBAC assignment for $($t.GroupName) - resource not available"
        }
    }

    # Gap: generate Automation Account credential if missing
    if ($aa) {
        $autoCredName = "superSecureXintraAutomation"
        try {
            $existingCred = Get-AzAutomationCredential -ResourceGroupName $ResourceGroupName -AutomationAccountName $uniqueAutomationAccountName -Name $autoCredName -ErrorAction SilentlyContinue
            if (-not $existingCred) {
                $pwdPlain = New-StrongPassword
                $pwdSecure = ConvertTo-SecureString $pwdPlain -AsPlainText -Force
                $null = New-AzAutomationCredential -ResourceGroupName $ResourceGroupName -AutomationAccountName $uniqueAutomationAccountName `
                    -Name $autoCredName -UserName $autoCredName -Password $pwdSecure
                Write-Host "`n--- Automation Account Credential ---" -ForegroundColor Cyan
                Write-Host "Credential Name: $autoCredName"
                Write-Host "Username:       $autoCredName"
                Write-Host "Password:       $pwdPlain"
            } else {
                Write-Host "Automation credential '$autoCredName' already exists." -ForegroundColor Yellow
            }
        } catch {
            Write-Warning "Failed to ensure automation credential '$autoCredName': $_"
        }
    } else {
        Write-Warning "Automation Account not found, skipping credential creation"
    }
}

<#
.SYNOPSIS
    Creates or updates a secret in Azure Key Vault.

.DESCRIPTION
    Stores a secret value in the specified Azure Key Vault. This function
    handles both creation of new secrets and updates to existing ones.

.PARAMETER VaultName
    The name of the Key Vault

.PARAMETER Name
    The name of the secret

.PARAMETER PlainValue
    The secret value to store

.OUTPUTS
    System.String
    The name of the created/updated secret
#>
function Set-KeyVaultSecret {
    param(
        [Parameter(Mandatory)] [string]$VaultName,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$PlainValue
    )
    # Secret names in Key Vault can contain only alphanumerics and dashes; normalize and warn if changed
    $normalized = ($Name -replace '[^0-9A-Za-z-]', '-').ToLower()
    if ($normalized -ne $Name) {
        Write-Warning "Key Vault secret name '$Name' is invalid. Using '$normalized' instead."
    }
    $secure = ConvertTo-SecureString $PlainValue -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $VaultName -Name $normalized -SecretValue $secure | Out-Null
    return $normalized
}

function New-SelfSignedCertificateForKeyVault {
    param([Parameter(Mandatory)][string]$CertName)
    
    try {
        Write-Verbose "Generating self-signed certificate: $CertName"
        
        # Create a self-signed certificate
        $cert = New-SelfSignedCertificate -Subject "CN=$CertName" -CertStoreLocation "cert:\CurrentUser\My" -KeyUsage DigitalSignature,KeyEncipherment -Type DocumentEncryptionCert -KeyExportPolicy Exportable
        
        # Export as PFX with a password
        $password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
        $pfxPath = Join-Path $env:TEMP "$CertName.pfx"
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password | Out-Null
        
        # Read the PFX file content
        $pfxBytes = [System.IO.File]::ReadAllBytes($pfxPath)
        $pfxBase64 = [System.Convert]::ToBase64String($pfxBytes)
        
        # Clean up
        Remove-Item $pfxPath -Force
        Remove-Item "cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
        
        return New-Object PSObject -Property @{ 
            Base64 = $pfxBase64
            Password = "P@ssw0rd123!"
            Thumbprint = $cert.Thumbprint
        }
        
    } catch {
        Write-Error "Failed to generate certificate: $($_.Exception.Message)"
        throw
    }
}

function Deploy-Network {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$AzureLocation,
        [Parameter(Mandatory)][string]$VNetName,
        [Parameter(Mandatory)][string]$SubnetName
    )
    # Create VNet + Subnet + NSG
    $vnet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $vnet) {
        $nsg = New-AzNetworkSecurityGroup -Name ($VNetName + "-nsg") -ResourceGroupName $ResourceGroupName -Location $AzureLocation
        # Allow SSH and RDP inbound from Internet (demo purposes)
        $null = Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name "Allow-SSH" -Description "Allow SSH" -Access Allow -Protocol Tcp -Direction Inbound -Priority 1000 -SourceAddressPrefix "*" -SourcePortRange "*" -DestinationAddressPrefix "*" -DestinationPortRange 22
        $null = Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name "Allow-RDP" -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 1010 -SourceAddressPrefix "*" -SourcePortRange "*" -DestinationAddressPrefix "*" -DestinationPortRange 3389
        $nsg | Set-AzNetworkSecurityGroup | Out-Null

        $vnet = New-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName -Location $AzureLocation -AddressPrefix "10.10.0.0/16"
        $null = Add-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix "10.10.1.0/24" -VirtualNetwork $vnet -NetworkSecurityGroupId $nsg.Id
        $vnet | Set-AzVirtualNetwork | Out-Null
        $vnet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName
    }

    $subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vnet
    return @{
        VNet = $vnet
        Subnet = $subnet
    }
}

function Deploy-LinuxVM {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$AzureLocation,
        [Parameter(Mandatory)][string]$VNetName,
        [Parameter(Mandatory)][string]$SubnetName,
        [Parameter(Mandatory)][string]$LinuxVmName,
        [Parameter(Mandatory)][string]$LinuxAdminUser,
        [Parameter(Mandatory)]$Subnet
    )
    
    # Create Public IP and NIC for Linux VM
    $linuxPip = New-AzPublicIpAddress -Name ($LinuxVmName + "-pip") -ResourceGroupName $ResourceGroupName -Location $AzureLocation -AllocationMethod Static -Sku Standard
    $linuxNic = New-AzNetworkInterface -Name ($LinuxVmName + "-nic") -ResourceGroupName $ResourceGroupName -Location $AzureLocation -SubnetId $Subnet.Id -PublicIpAddressId $linuxPip.Id

    # Linux VM (Ubuntu 22.04 LTS Gen2), system assigned identity (with password authentication for lab purposes)
    try {
        $linuxCred = New-Object System.Management.Automation.PSCredential($LinuxAdminUser,(ConvertTo-SecureString (New-StrongPassword) -AsPlainText -Force))
        $linuxVmConfig = New-AzVMConfig -VMName $LinuxVmName -VMSize "Standard_D2s_v5" -IdentityType SystemAssigned
        $linuxVmConfig = Set-AzVMOperatingSystem -VM $linuxVmConfig -Linux -ComputerName $LinuxVmName -Credential $linuxCred
        $linuxVmConfig = Set-AzVMSourceImage -VM $linuxVmConfig -PublisherName "Canonical" -Offer "0001-com-ubuntu-server-jammy" -Skus "22_04-lts-gen2" -Version "latest"
        $linuxVmConfig = Set-AzVMOSDisk -VM $linuxVmConfig -CreateOption FromImage -Name ($LinuxVmName + "-osdisk") -StorageAccountType "Premium_LRS"
        $linuxVmConfig = Add-AzVMNetworkInterface -VM $linuxVmConfig -Id $linuxNic.Id -Primary
        $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AzureLocation -VM $linuxVmConfig -Tag @{ purpose="lab"; os="linux" } -Verbose
        Write-Host "✅ Created Linux VM: $LinuxVmName" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to create Linux VM: $($_.Exception.Message)"
        Write-Host "Retrying with different configuration..." -ForegroundColor Yellow
        try {
            # Try with simpler New-AzVM syntax
            $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AzureLocation -Name $LinuxVmName -Size "Standard_D2s_v5" `
                -Image "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest" -Credential $linuxCred `
                -VirtualNetworkName $VNetName -SubnetName $SubnetName -PublicIpAddressName ($LinuxVmName + "-pip") `
                -OpenPorts 22,80,443 -Tag @{ purpose="lab"; os="linux" }
            Write-Host "✅ Created Linux VM: $LinuxVmName (simplified method)" -ForegroundColor Green
        } catch {
            Write-Error "Failed to create Linux VM with both methods: $($_.Exception.Message)"
            throw
        }
    }
    
    # Enable Azure AD Login extension
    try {
        Set-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $LinuxVmName -Location $AzureLocation -Publisher "Microsoft.Azure.ActiveDirectory" -ExtensionType "AADSSHLoginForLinux" -Name "AADSSHLoginForLinux" -TypeHandlerVersion "1.0" | Out-Null
        Write-Host "✅ Enabled Azure AD SSH Login for Linux VM" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to enable Azure AD SSH Login: $($_.Exception.Message)"
    }

    return Get-AzVM -Name $LinuxVmName -ResourceGroupName $ResourceGroupName
}

function Get-AvailableWindowsImage {
    param(
        [Parameter(Mandatory)][string]$AzureLocation
    )
    
    Write-Host "Searching for available Windows images in $AzureLocation..." -ForegroundColor Yellow
    
    # Try to find Windows 11 22H2 images
    try {
        $win11Images = Get-AzVMImageSku -Location $AzureLocation -PublisherName "MicrosoftWindowsDesktop" -Offer "Windows-11" -ErrorAction SilentlyContinue
        if ($win11Images) {
            $win11_22h2 = $win11Images | Where-Object { $_.Skus -like "*22h2*" -and $_.Skus -like "*pro*" } | Select-Object -First 1
            if ($win11_22h2) {
                Write-Host "Found Windows 11 22H2 Pro: $($win11_22h2.Skus)" -ForegroundColor Green
                return @{
                    Publisher = "MicrosoftWindowsDesktop"
                    Offer = "Windows-11"
                    Sku = $win11_22h2.Skus
                    Name = "Windows 11 22H2 Pro"
                }
            }
            
            # Try any Windows 11 Pro
            $win11Pro = $win11Images | Where-Object { $_.Skus -like "*pro*" } | Select-Object -First 1
            if ($win11Pro) {
                Write-Host "Found Windows 11 Pro: $($win11Pro.Skus)" -ForegroundColor Green
                return @{
                    Publisher = "MicrosoftWindowsDesktop"
                    Offer = "Windows-11"
                    Sku = $win11Pro.Skus
                    Name = "Windows 11 Pro"
                }
            }
        }
    } catch {
        Write-Warning "Could not query Windows 11 images: $($_.Exception.Message)"
    }
    
    # Fallback to Windows 10
    try {
        $win10Images = Get-AzVMImageSku -Location $AzureLocation -PublisherName "MicrosoftWindowsDesktop" -Offer "Windows-10" -ErrorAction SilentlyContinue
        if ($win10Images) {
            $win10_22h2 = $win10Images | Where-Object { $_.Skus -like "*22h2*" -and $_.Skus -like "*pro*" } | Select-Object -First 1
            if ($win10_22h2) {
                Write-Host "Fallback: Found Windows 10 22H2 Pro: $($win10_22h2.Skus)" -ForegroundColor Yellow
                return @{
                    Publisher = "MicrosoftWindowsDesktop"
                    Offer = "Windows-10"
                    Sku = $win10_22h2.Skus
                    Name = "Windows 10 22H2 Pro"
                }
            }
            
            # Try any Windows 10 Pro
            $win10Pro = $win10Images | Where-Object { $_.Skus -like "*pro*" } | Select-Object -First 1
            if ($win10Pro) {
                Write-Host "Fallback: Found Windows 10 Pro: $($win10Pro.Skus)" -ForegroundColor Yellow
                return @{
                    Publisher = "MicrosoftWindowsDesktop"
                    Offer = "Windows-10"
                    Sku = $win10Pro.Skus
                    Name = "Windows 10 Pro"
                }
            }
        }
    } catch {
        Write-Warning "Could not query Windows 10 images: $($_.Exception.Message)"
    }
    
    # Final fallback to Windows Server 2022
    Write-Host "Final fallback: Using Windows Server 2022" -ForegroundColor Red
    return @{
        Publisher = "MicrosoftWindowsServer"
        Offer = "WindowsServer"
        Sku = "2022-datacenter"
        Name = "Windows Server 2022"
    }
}

function Deploy-WindowsVM {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$AzureLocation,
        [Parameter(Mandatory)][string]$VNetName,
        [Parameter(Mandatory)][string]$SubnetName,
        [Parameter(Mandatory)][string]$WindowsVmName,
        [Parameter(Mandatory)][string]$WindowsAdminUser,
        [Parameter(Mandatory)]$Subnet
    )
    
    # Find available Windows image
    $windowsImage = Get-AvailableWindowsImage -AzureLocation $AzureLocation
    Write-Host "Using image: $($windowsImage.Name)" -ForegroundColor Cyan
    
    # Create Public IP and NIC for Windows VM
    $winPip = New-AzPublicIpAddress -Name ($WindowsVmName + "-pip") -ResourceGroupName $ResourceGroupName -Location $AzureLocation -AllocationMethod Static -Sku Standard
    $winNic = New-AzNetworkInterface -Name ($WindowsVmName + "-nic") -ResourceGroupName $ResourceGroupName -Location $AzureLocation -SubnetId $Subnet.Id -PublicIpAddressId $winPip.Id

    # Windows VM with system assigned identity
    try {
        $winCred = New-Object System.Management.Automation.PSCredential($WindowsAdminUser,(ConvertTo-SecureString (New-StrongPassword) -AsPlainText -Force))
        $winVmConfig = New-AzVMConfig -VMName $WindowsVmName -VMSize "Standard_D2s_v5" -IdentityType SystemAssigned
        $winVmConfig = Set-AzVMOperatingSystem -VM $winVmConfig -Windows -ComputerName $WindowsVmName -Credential $winCred -ProvisionVMAgent -EnableAutoUpdate
        $winVmConfig = Set-AzVMSourceImage -VM $winVmConfig -PublisherName $windowsImage.Publisher -Offer $windowsImage.Offer -Skus $windowsImage.Sku -Version "latest"
        $winVmConfig = Set-AzVMOSDisk -VM $winVmConfig -CreateOption FromImage -Name ($WindowsVmName + "-osdisk") -StorageAccountType "Premium_LRS"
        $winVmConfig = Add-AzVMNetworkInterface -VM $winVmConfig -Id $winNic.Id -Primary
        # Disable Trusted Launch to avoid security type issues
        $winVmConfig = Set-AzVMSecurityProfile -VM $winVmConfig -SecurityType "Standard"
        $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AzureLocation -VM $winVmConfig -Tag @{ purpose="lab"; os="windows" } -Verbose
        Write-Host "✅ Created Windows VM: $WindowsVmName ($($windowsImage.Name))" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to create Windows VM: $($_.Exception.Message)"
        Write-Host "Retrying with different Windows 11 22H2 configuration..." -ForegroundColor Yellow
        try {
            # Try with alternative configuration (Standard LRS storage)
            $winVmConfig = New-AzVMConfig -VMName $WindowsVmName -VMSize "Standard_D2s_v5" -IdentityType SystemAssigned
            $winVmConfig = Set-AzVMOperatingSystem -VM $winVmConfig -Windows -ComputerName $WindowsVmName -Credential $winCred -ProvisionVMAgent -EnableAutoUpdate
            $winVmConfig = Set-AzVMSourceImage -VM $winVmConfig -PublisherName $windowsImage.Publisher -Offer $windowsImage.Offer -Skus $windowsImage.Sku -Version "latest"
            $winVmConfig = Set-AzVMOSDisk -VM $winVmConfig -CreateOption FromImage -Name ($WindowsVmName + "-osdisk") -StorageAccountType "Standard_LRS"
            $winVmConfig = Add-AzVMNetworkInterface -VM $winVmConfig -Id $winNic.Id -Primary
            # Explicitly disable Trusted Launch
            $winVmConfig = Set-AzVMSecurityProfile -VM $winVmConfig -SecurityType "Standard"
            $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AzureLocation -VM $winVmConfig -Tag @{ purpose="lab"; os="windows" } -Verbose
            Write-Host "✅ Created Windows VM: $WindowsVmName ($($windowsImage.Name) with Standard LRS)" -ForegroundColor Green
        } catch {
            Write-Warning "Second Windows 11 22H2 attempt failed: $($_.Exception.Message)"
            Write-Host "Trying Windows 11 22H2 with different VM size..." -ForegroundColor Yellow
            try {
                # Try with different VM size
                $winVmConfig = New-AzVMConfig -VMName $WindowsVmName -VMSize "Standard_B2s" -IdentityType SystemAssigned
                $winVmConfig = Set-AzVMOperatingSystem -VM $winVmConfig -Windows -ComputerName $WindowsVmName -Credential $winCred -ProvisionVMAgent -EnableAutoUpdate
                $winVmConfig = Set-AzVMSourceImage -VM $winVmConfig -PublisherName $windowsImage.Publisher -Offer $windowsImage.Offer -Skus $windowsImage.Sku -Version "latest"
                $winVmConfig = Set-AzVMOSDisk -VM $winVmConfig -CreateOption FromImage -Name ($WindowsVmName + "-osdisk") -StorageAccountType "Standard_LRS"
                $winVmConfig = Add-AzVMNetworkInterface -VM $winVmConfig -Id $winNic.Id -Primary
                $winVmConfig = Set-AzVMSecurityProfile -VM $winVmConfig -SecurityType "Standard"
                $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AzureLocation -VM $winVmConfig -Tag @{ purpose="lab"; os="windows" } -Verbose
                Write-Host "✅ Created Windows VM: $WindowsVmName ($($windowsImage.Name) with B2s size)" -ForegroundColor Green
            } catch {
                Write-Warning "Windows Server fallback also failed: $($_.Exception.Message)"
                Write-Host "Trying completely simplified approach..." -ForegroundColor Yellow
                try {
                    # Clean up any partially created resources
                    try { 
                        $existingPip = Get-AzPublicIpAddress -Name ($WindowsVmName + "-pip") -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
                        if ($existingPip) { Remove-AzPublicIpAddress -Name ($WindowsVmName + "-pip") -ResourceGroupName $ResourceGroupName -Force }
                    } catch {}
                    try { 
                        $existingNic = Get-AzNetworkInterface -Name ($WindowsVmName + "-nic") -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
                        if ($existingNic) { Remove-AzNetworkInterface -Name ($WindowsVmName + "-nic") -ResourceGroupName $ResourceGroupName -Force }
                    } catch {}
                    
                    # Final attempt: Use simplified syntax with available image
                    $imageString = "$($windowsImage.Publisher):$($windowsImage.Offer):$($windowsImage.Sku):latest"
                    $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AzureLocation -Name $WindowsVmName -Size "Standard_B2s" `
                        -Image $imageString -Credential $winCred `
                        -VirtualNetworkName $VNetName -SubnetName $SubnetName `
                        -SecurityGroupName ($WindowsVmName + "-nsg") -PublicIpAddressName ($WindowsVmName + "-pip2") `
                        -OpenPorts 3389,80,443
                    Write-Host "✅ Created Windows VM: $WindowsVmName ($($windowsImage.Name) simplified method)" -ForegroundColor Green
                } catch {
                    Write-Error "Failed to create Windows VM with all methods: $($_.Exception.Message)"
                    throw
                }
            }
        }
    }

    # Enable Azure AD Login extension
    try {
        Set-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $WindowsVmName -Location $AzureLocation -Publisher "Microsoft.Azure.ActiveDirectory" -ExtensionType "AADLoginForWindows" -Name "AADLoginForWindows" -TypeHandlerVersion "1.0" | Out-Null
        Write-Host "✅ Enabled Azure AD Login for Windows VM" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to enable Azure AD Login: $($_.Exception.Message)"
    }

    return Get-AzVM -Name $WindowsVmName -ResourceGroupName $ResourceGroupName
}

# Access package creation has been moved to manual steps - see README.md

function Install-AzureCLIOnWindowsVM {
    param(
        [Parameter(Mandatory)] [string]$ResourceGroupName,
        [Parameter(Mandatory)] [string]$VmName
    )
    Write-Host "Installing Azure CLI on VM '$VmName'..." -ForegroundColor Cyan
    $script = @'
$ErrorActionPreference = "Stop"
if (Get-Command az -ErrorAction SilentlyContinue) {
    Write-Output "Azure CLI already installed."
    exit 0
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$msi = Join-Path $env:TEMP "AzureCLI.msi"
Invoke-WebRequest -Uri "https://aka.ms/installazurecliwindows" -OutFile $msi
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /qn /norestart"
Remove-Item $msi -Force -ErrorAction SilentlyContinue
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw "Azure CLI installation failed." }
az --version
'@
    Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VmName -CommandId 'RunPowerShellScript' -ScriptString $script | Out-Null
    Write-Host "Azure CLI installed (or already present) on '$VmName'." -ForegroundColor Green
}

# Main
Test-DeploymentPrerequisites
Install-GraphModule
Connect-ToMicrosoftGraph
Ensure-AzModulesAndLogin
$domain = Get-TenantDefaultDomain

$usersToCreate = @(
    @{ Prefix="global.admin";           Display="Global Admin User";                   Role="Global Administrator" }
    @{ Prefix="cloudapp.admin";         Display="Cloud Application Admin User";        Role="Cloud Application Administrator" }
    @{ Prefix="user.admin";             Display="User Admin User";                     Role="User Administrator" }
    @{ Prefix="privilegedrole.admin";   Display="Privileged Role Admin User";          Role="Privileged Role Administrator" }
    @{ Prefix="demo1";                  Display="Demo user 1";                         Role=$null }
    @{ Prefix="demo2";                  Display="Demo user 2";                         Role=$null }
    @{ Prefix="demo3";                  Display="Demo user 3";                         Role=$null }
    @{ Prefix="demo4";                  Display="Demo user 4";                         Role=$null }
    @{ Prefix="demo5";                  Display="Demo user 5";                         Role=$null }
)

$createdOutput = @()

foreach ($entry in $usersToCreate) {
    # Access hashtable properties directly (compatible with Constrained Language Mode)
    $prefix = $entry['Prefix']
    $display = $entry['Display'] 
    $role = $entry['Role']
    
    $upn = "{0}@{1}" -f $prefix, $domain
    $mailNick = ($prefix -replace '[^a-z0-9]', '')
    Write-Host "Ensuring user: $upn" -ForegroundColor Green
    $result = New-LabUser -UserPrincipalName $upn -DisplayName $display -MailNickname $mailNick
    if ($role) {
        Write-Host "  Ensuring role assignment: $role" -ForegroundColor DarkGreen
        Set-UserDirectoryRoleAssignment -User $result.User -RoleDisplayName $role
    }
    
    # Create output object using New-Object (Constrained Language Mode compatible)
    $outputEntry = New-Object PSObject -Property @{
        UserPrincipalName = $upn
        DisplayName       = $display
        AssignedRole      = $role
        TempPassword      = $result.Password
        CreatedNow        = $result.Created
    }
    $createdOutput += $outputEntry
}

# Ensure required security groups exist
$groupsToEnsure = @(
    'lic-m365-e3',
    'lic-m365-p2',
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
    # --- New: Storage RBAC groups ---
    'perm-xintrastore-reader',
    'perm-xintrastore-contributer',
    'perm-xintrastore-owner'
)

$groupResults = @()
foreach ($g in $groupsToEnsure) {
    Write-Host "Ensuring group: $g" -ForegroundColor Green
    $res = New-LabSecurityGroup -DisplayName $g
    $groupResultObj = New-Object PSObject -Property @{
        DisplayName = $g
        ObjectId    = $res.Group.Id
        CreatedNow  = $res.Created
    }
    $groupResults += $groupResultObj
}

# Add all created users to license groups (lic-m365-e3, lic-m365-P2, lic-m365-e5)
Write-Host "`nAdding users to license groups..." -ForegroundColor Cyan
$licenseGroupNames = @('lic-m365-e3','lic-m365-P2','lic-m365-e5')
$licenseGroups = @{}
foreach ($name in $licenseGroupNames) {
    $grp = Get-MgGroup -Filter "displayName eq '$name'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($grp) { 
        $licenseGroups[$name] = $grp
        Write-Host "  Found license group: $name (ID: $($grp.Id))" -ForegroundColor Gray
    } else { 
        Write-Warning "License group not found: $name" 
    }
}

foreach ($row in $createdOutput) {
    try {
        $userObj = Get-MgUser -UserId $row.UserPrincipalName -ErrorAction Stop
        Write-Host "Processing user: $($userObj.UserPrincipalName)" -ForegroundColor Cyan
    } catch {
        Write-Warning "User not found, skipping license assignment: $($row.UserPrincipalName)"
        continue
    }
    
    # Add user to each license group individually
    foreach ($groupName in $licenseGroupNames) {
        if (-not $licenseGroups.ContainsKey($groupName)) {
            Write-Warning "Skipping group '$groupName' - not found"
            continue
        }
        
        $group = $licenseGroups[$groupName]
        $groupId = $group.Id
        
        # Check if user is already a member of this specific group
        $userAlreadyInGroup = $false
        try {
            $existingMember = Get-MgGroupMember -GroupId $groupId -Filter "id eq '$($userObj.Id)'" -ErrorAction SilentlyContinue
            if ($existingMember) {
                $userAlreadyInGroup = $true
                Write-Host "    ✓ User already in group: $groupName" -ForegroundColor Gray
            }
        } catch {
            # If filtering doesn't work, fall back to checking all members
            try {
                $groupMembers = Get-MgGroupMember -GroupId $groupId -ErrorAction Stop
                $members = @($groupMembers)  # Force into array to handle single objects
                
                foreach ($member in $members) {
                    $memberId = $null
                    if ($member.Id) {
                        $memberId = $member.Id
                    } elseif ($member.ObjectId) {
                        $memberId = $member.ObjectId
                    } elseif ($member -is [string]) {
                        $memberId = $member
                    }
                    
                    if ($memberId -eq $userObj.Id) {
                        $userAlreadyInGroup = $true
                        Write-Host "    ✓ User already in group: $groupName" -ForegroundColor Gray
                        break
                    }
                }
            } catch {
                Write-Verbose "Could not retrieve existing group members for group $groupName : $($_.Exception.Message)"
            }
        }
        
        # Add to group if not already a member
        if (-not $userAlreadyInGroup) {
            try {
                # Use New-MgGroupMemberByRef which is the current method for adding group members
                $memberRef = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($userObj.Id)"
                }
                New-MgGroupMemberByRef -GroupId $groupId -BodyParameter $memberRef -ErrorAction Stop
                Write-Host "    ✓ Added $($userObj.UserPrincipalName) to $groupName" -ForegroundColor Green
            } catch {
                if ($_.Exception.Message -like "*One or more added object references already exist*" -or 
                    $_.Exception.Message -like "*already exist*") {
                    Write-Host "    ✓ User already in group: $groupName (via error)" -ForegroundColor Gray
                } else {
                    Write-Warning "    ✗ Failed to add $($userObj.UserPrincipalName) to $groupName : $($_.Exception.Message)"
                }
            }
        }
    }
}

# Enterprise applications
Write-Host "`nCreating enterprise applications..." -ForegroundColor Cyan
$appResults = New-LabEnterpriseApplications

# --- New: App registration with Contributor on subscription and assign to all users ---
Write-Host "`nEnsuring 'xintra contributor app' with subscription Contributor and user assignments..." -ForegroundColor Cyan
$subId = (Get-AzContext).Subscription.Id
$appName = "xintra contributor app"

# Ensure application + service principal
$xcApp = Get-MgApplication -Filter "displayName eq '$appName'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
$xcCreated = $false
if (-not $xcApp) {
    $xcApp = New-MgApplication -DisplayName $appName -SignInAudience "AzureADMyOrg"
    $xcCreated = $true
}
$xcSp = Get-MgServicePrincipal -Filter "appId eq '$($xcApp.AppId)'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $xcSp) { 
    try {
        $xcSp = New-MgServicePrincipal -AppId $xcApp.AppId
    } catch {
        Write-Warning "Failed to create service principal for '$appName': $($_.Exception.Message)"
        throw
    }
}

# Create client secret on first creation
$xcSecretValue = $null
if ($xcCreated) {
    try {
        # Create password credential (DisplayName parameter may vary by module version)
        $passwordCredential = @{
            displayName = "DefaultSecret"
        }
        $xcSecret = Add-MgApplicationPassword -ApplicationId $xcApp.Id -PasswordCredential $passwordCredential
        $xcSecretValue = $xcSecret.SecretText
    } catch {
        # Fallback method if the above fails
        try {
            $xcSecret = Add-MgApplicationPassword -ApplicationId $xcApp.Id
            $xcSecretValue = $xcSecret.SecretText
        } catch {
            Write-Warning "Failed to create client secret for '$appName': $($_.Exception.Message)"
            $xcSecretValue = $null
        }
    }
}

# Grant Contributor at subscription scope to the service principal
try {
    New-AzRoleAssignment -ObjectId $xcSp.Id -RoleDefinitionName "Contributor" -Scope "/subscriptions/$subId" -ErrorAction Stop | Out-Null
    Write-Host "Assigned 'Contributor' on subscription to SP: $($xcSp.DisplayName)" -ForegroundColor DarkGreen
} catch {
    if ($_.Exception.Message -notmatch 'already exists') {
        Write-Warning "Failed to assign Contributor to SP '$($xcSp.DisplayName)': $_"
    }
}

# Assign the app to all Member users (default role assignment)
$allUsers = @()
try {
    $allUsers = Get-MgUser -Filter "userType eq 'Member'" -ErrorAction Stop
} catch {
    Write-Warning "Failed to enumerate users for app assignment: $_"
}
foreach ($u in $allUsers) {
    try {
        # Default role assignment uses Guid.Empty for appRoleId
        New-MgUserAppRoleAssignment -UserId $u.Id -BodyParameter @{
            principalId = $u.Id
            resourceId  = $xcSp.Id
            appRoleId   = [Guid]::Empty
        } -ErrorAction Stop | Out-Null
        Write-Host "Assigned app '$appName' to user $($u.UserPrincipalName)" -ForegroundColor DarkGreen
    } catch {
        if ($_.Exception.Message -notlike "*already exist*") {
            Write-Warning "Failed to assign app '$appName' to $($u.UserPrincipalName): $_"
        }
    }
}

# Track in export
$xcAppResultObj = New-Object PSObject -Property @{
    DisplayName = $appName
    AppId       = $xcApp.AppId
    Secret      = $xcSecretValue
    TenantId    = (Get-MgContext).TenantId
    CreatedNow  = $xcCreated
}
$appResults += $xcAppResultObj

# Access Package creation moved to manual steps - see Step 6 in README.md
Write-Host "⚠️  Access Package creation must be done manually - see README.md Step 6" -ForegroundColor Yellow

# Deploy Azure infrastructure and assign RBAC (Key Vault, Automation, Log Analytics)
Write-Host "`nDeploying Azure infrastructure..." -ForegroundColor Cyan
Deploy-Infrastructure -ResourceGroupName $ResourceGroupName -AzureLocation $AzureLocation -KeyVaultName $KeyVaultName `
    -AutomationAccountName $AutomationAccountName -LogAnalyticsWorkspaceName $LogAnalyticsWorkspaceName `
    -StorageAccountName $StorageAccountName

# Use the actual unique names created by the infrastructure deployment
$ActualKeyVaultName = if ($script:ActualKeyVaultName) { $script:ActualKeyVaultName } else { $KeyVaultName }
$ActualStorageAccountName = if ($script:ActualStorageAccountName) { $script:ActualStorageAccountName } else { $StorageAccountName }
$ActualAutomationAccountName = if ($script:ActualAutomationAccountName) { $script:ActualAutomationAccountName } else { $AutomationAccountName }
$ActualLogAnalyticsWorkspaceName = if ($script:ActualLogAnalyticsWorkspaceName) { $script:ActualLogAnalyticsWorkspaceName } else { $LogAnalyticsWorkspaceName }

Write-Host "Using actual resource names for subsequent operations:" -ForegroundColor Cyan
Write-Host "  Key Vault: $ActualKeyVaultName" -ForegroundColor Gray
Write-Host "  Storage Account: $ActualStorageAccountName" -ForegroundColor Gray

# Ensure Key Vault permissions before creating secrets
Write-Host "Verifying Key Vault permissions..." -ForegroundColor Cyan
$canCreateSecrets = $false

if ($ActualKeyVaultName) {
    try {
        # Try to test permissions by attempting to get access policies
        $testVault = Get-AzKeyVault -VaultName $ActualKeyVaultName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if ($testVault) {
            # Try to add current user permissions if not already set
            $currentContext = Get-AzContext
            if ($currentContext -and $currentContext.Account) {
                Write-Host "  Adding Key Vault permissions for current user..." -ForegroundColor Gray
                
                # Try using the Object ID from the error message (if available)
                $currentUserObjectId = "31809977-bb60-4115-bc71-14eec1ed1672"  # From the error message
                
                try {
                    Set-AzKeyVaultAccessPolicy -VaultName $ActualKeyVaultName -ObjectId $currentUserObjectId `
                        -PermissionsToSecrets Get,List,Set,Delete,Backup,Restore,Recover,Purge `
                        -ErrorAction Stop | Out-Null
                    Write-Host "  ✓ Added access policy using user object ID" -ForegroundColor Green
                    $canCreateSecrets = $true
                } catch {
                    # Try RBAC approach as fallback
                    try {
                        $kvResourceId = "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$ActualKeyVaultName"
                        New-AzRoleAssignment -ObjectId $currentUserObjectId -RoleDefinitionName "Key Vault Secrets Officer" -Scope $kvResourceId -ErrorAction Stop | Out-Null
                        Write-Host "  ✓ Added RBAC Key Vault Secrets Officer role" -ForegroundColor Green
                        Start-Sleep -Seconds 10  # Wait for RBAC propagation
                        $canCreateSecrets = $true
                    } catch {
                        Write-Warning "  Failed to add Key Vault permissions: $($_.Exception.Message)"
                    }
                }
            }
        }
    } catch {
        Write-Warning "Could not access Key Vault for permission setup: $($_.Exception.Message)"
    }
    
    # Test if we can create secrets
    if ($canCreateSecrets) {
        try {
            # Test with a dummy secret
            $testSecret = ConvertTo-SecureString "test" -AsPlainText -Force
            Set-AzKeyVaultSecret -VaultName $ActualKeyVaultName -Name "test-permission" -SecretValue $testSecret -ErrorAction Stop | Out-Null
            Remove-AzKeyVaultSecret -VaultName $ActualKeyVaultName -Name "test-permission" -Force -ErrorAction SilentlyContinue | Out-Null
            $canCreateSecrets = $true
            Write-Host "  ✓ Key Vault permissions verified" -ForegroundColor Green
        } catch {
            $canCreateSecrets = $false
            Write-Warning "  Key Vault permission test failed: $($_.Exception.Message)"
        }
    }
}

if ($canCreateSecrets) {
    # Add required Key Vault secret
    Write-Host "Adding lab secret to Key Vault..." -ForegroundColor Cyan
    try {
        Set-KeyVaultSecret -VaultName $ActualKeyVaultName -Name "lab-secret" -PlainValue "This is a vulnerable lab secret - should not be here!" | Out-Null
        Write-Host "✓ Added 'lab-secret' to Key Vault" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to create 'lab-secret' secret: $($_.Exception.Message)"
    }

    # Generate and store a self-signed certificate
    Write-Host "Generating self-signed certificate and storing in Key Vault..." -ForegroundColor Cyan
    try {
        $cert = New-SelfSignedCertificateForKeyVault -CertName "lab-certificate"
        
        # Import certificate to Key Vault (requires certificate permissions)
        try {
            $pfxBytes = [System.Convert]::FromBase64String($cert.Base64)
            $securePassword = ConvertTo-SecureString $cert.Password -AsPlainText -Force
            Import-AzKeyVaultCertificate -VaultName $ActualKeyVaultName -Name "lab-certificate" -CertificateString $cert.Base64 -Password $securePassword | Out-Null
            Write-Host "✓ Self-signed certificate generated and stored in Key Vault" -ForegroundColor Green
        } catch {
            # If certificate import fails, store as secret instead
            Set-KeyVaultSecret -VaultName $ActualKeyVaultName -Name "lab-certificate-pfx" -PlainValue $cert.Base64 | Out-Null
            Set-KeyVaultSecret -VaultName $ActualKeyVaultName -Name "lab-certificate-password" -PlainValue $cert.Password | Out-Null
            Write-Host "✓ Self-signed certificate generated and stored as secrets in Key Vault" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to generate/store certificate: $($_.Exception.Message)"
    }
} else {
    Write-Warning "Cannot create Key Vault secrets due to insufficient permissions"
    Write-Host "  Please manually grant yourself 'Key Vault Secrets Officer' role on the Key Vault" -ForegroundColor Yellow
    Write-Host "  Or run: az keyvault set-policy --name $ActualKeyVaultName --object-id 31809977-bb60-4115-bc71-14eec1ed1672 --secret-permissions get list set delete" -ForegroundColor Gray
}

# Lookup Demo user 2 and 3 object IDs
$demo2Upn = "demo2@$domain"
$demo3Upn = "demo3@$domain"
$demo2 = Get-MgUser -UserId $demo2Upn
$demo3 = Get-MgUser -UserId $demo3Upn

# Grant Demo2 and Demo3 access to read Key Vault secrets
$kv = Get-AzKeyVault -VaultName $ActualKeyVaultName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if ($kv) {
    foreach ($u in @($demo2, $demo3)) {
        try {
            New-AzRoleAssignment -ObjectId $u.Id -RoleDefinitionName "Key Vault Secrets User" -Scope $kv.ResourceId -ErrorAction Stop | Out-Null
            Write-Host "Granted 'Key Vault Secrets User' on $ActualKeyVaultName to $($u.UserPrincipalName)"
        } catch {
            if ($_.Exception.Message -notmatch 'already exists') {
                Write-Warning "Failed to grant KV role to $($u.UserPrincipalName): $_"
            }
        }
    }
} else {
    Write-Warning "Key Vault not found, skipping RBAC assignments"
}

# Deploy Network and VMs
Write-Host "`nDeploying network infrastructure..." -ForegroundColor Cyan
$network = Deploy-Network -ResourceGroupName $ResourceGroupName -AzureLocation $AzureLocation `
    -VNetName "xintra-vnet" -SubnetName "subnet1"

Write-Host "`nDeploying Linux virtual machine..." -ForegroundColor Cyan
$linuxVm = Deploy-LinuxVM -ResourceGroupName $ResourceGroupName -AzureLocation $AzureLocation `
    -VNetName "xintra-vnet" -SubnetName "subnet1" `
    -LinuxVmName "xintra-ubuntu" -LinuxAdminUser "azureuser" `
    -Subnet $network.Subnet

Write-Host "`nDeploying Windows virtual machine..." -ForegroundColor Cyan
$winVm = Deploy-WindowsVM -ResourceGroupName $ResourceGroupName -AzureLocation $AzureLocation `
    -VNetName "xintra-vnet" -SubnetName "subnet1" `
    -WindowsVmName "xintra-win11" -WindowsAdminUser "azureadmin" `
    -Subnet $network.Subnet

# Install Azure CLI inside the Windows VM
Install-AzureCLIOnWindowsVM -ResourceGroupName $ResourceGroupName -VmName $winVm.Name

# Grant Key Vault Administrator to Linux VM system-assigned managed identity
if ($kv -and $linuxVm.Identity -and $linuxVm.Identity.PrincipalId) {
    try {
        New-AzRoleAssignment -ObjectId $linuxVm.Identity.PrincipalId -RoleDefinitionName "Key Vault Administrator" -Scope $kv.ResourceId -ErrorAction Stop | Out-Null
        Write-Host "Granted 'Key Vault Administrator' on $ActualKeyVaultName to Linux VM system-managed identity" -ForegroundColor DarkGreen
    } catch {
        if ($_.Exception.Message -notmatch 'already exists') {
            Write-Warning "Failed to grant KV Admin to Linux VM identity: $_"
        }
    }
} else {
    if (-not $kv) {
        Write-Warning "Key Vault not found; skipping KV Admin RBAC."
    } else {
        Write-Warning "Linux VM identity principal not found; skipping KV Admin RBAC."
    }
}

# Assign RBAC: Virtual Machine User Login to Demo2 and Demo3 on both VMs
foreach ($u in @($demo2, $demo3)) {
    foreach ($vm in @($linuxVm, $winVm)) {
        try {
            New-AzRoleAssignment -ObjectId $u.Id -RoleDefinitionName "Virtual Machine User Login" -Scope $vm.Id -ErrorAction Stop | Out-Null
            Write-Host "Granted 'Virtual Machine User Login' on $($vm.Name) to $($u.UserPrincipalName)"
        } catch {
            if ($_.Exception.Message -notmatch 'already exists') {
                Write-Warning "Failed to grant VM login to $($u.UserPrincipalName) on $($vm.Name): $_"
            }
        }
    }
}

# Create user-assigned managed identity and attach to Windows VM; grant KV and subscription Owner
$uamiName = "xintra-win11-uami"
$uami = Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $uamiName -ErrorAction SilentlyContinue
if (-not $uami) {
    $uami = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $uamiName -Location $AzureLocation
}

# Properly update VM to have both system-assigned and user-assigned managed identity
try {
    $vmObj = Get-AzVM -Name $winVm.Name -ResourceGroupName $ResourceGroupName
    
    # Initialize Identity if it doesn't exist
    if (-not $vmObj.Identity) {
        $vmObj.Identity = @{}
    }
    
    # Set the identity type and user-assigned identities
    $vmObj.Identity.Type = "SystemAssigned,UserAssigned"
    
    # Initialize UserAssignedIdentities if it doesn't exist
    if (-not $vmObj.Identity.UserAssignedIdentities) {
        $vmObj.Identity.UserAssignedIdentities = @{}
    }
    
    # Add the user-assigned managed identity
    $vmObj.Identity.UserAssignedIdentities[$uami.Id] = @{}
    
    Update-AzVM -ResourceGroupName $ResourceGroupName -VM $vmObj | Out-Null
    Write-Host "✅ Added user-assigned managed identity to Windows VM" -ForegroundColor Green
} catch {
    Write-Warning "Failed to add user-assigned managed identity using VM object update: $($_.Exception.Message)"
    Write-Host "Trying alternative method..." -ForegroundColor Yellow
    try {
        # Alternative method using Update-AzVM with specific identity parameters
        $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $winVm.Name
        $vm = Update-AzVM -ResourceGroupName $ResourceGroupName -VM $vm -IdentityType "SystemAssigned,UserAssigned" -IdentityID $uami.Id
        Write-Host "✅ Added user-assigned managed identity to Windows VM (alternative method)" -ForegroundColor Green
    } catch {
        Write-Error "Failed to add user-assigned managed identity with both methods: $($_.Exception.Message)"
    }
}

# RBAC for UAMI
$subId = (Get-AzContext).Subscription.Id
if ($kv) {
    try {
        New-AzRoleAssignment -ObjectId $uami.PrincipalId -RoleDefinitionName "Key Vault Secrets User" -Scope $kv.ResourceId -ErrorAction Stop | Out-Null
        Write-Host "Granted 'Key Vault Secrets User' to Windows UAMI on $ActualKeyVaultName" -ForegroundColor DarkGreen
    } catch { if ($_.Exception.Message -notmatch 'already exists') { Write-Warning $_ } }
} else {
    Write-Warning "Key Vault not found, skipping UAMI Key Vault RBAC"
}
try {
    New-AzRoleAssignment -ObjectId $uami.PrincipalId -RoleDefinitionName "Owner" -Scope "/subscriptions/$subId" -ErrorAction Stop | Out-Null
} catch { if ($_.Exception.Message -notmatch 'already exists') { Write-Warning $_ } }

# Also grant Global Administrator directory role to the Windows UAMI service principal
try {
    $gaRole = Enable-DirectoryRole -DisplayName "Global Administrator"
    
    # Check if UAMI is already assigned to the Global Administrator role
    $uamiAlreadyHasRole = $false
    try {
        $gaMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -ErrorAction Stop
        $members = @($gaMembers)  # Force into array to handle single objects
        
        if ($members.Length -gt 0) {
            foreach ($member in $members) {
                $memberId = $null
                if ($member.Id) {
                    $memberId = $member.Id
                } elseif ($member.ObjectId) {
                    $memberId = $member.ObjectId
                } elseif ($member.AdditionalProperties -and $member.AdditionalProperties.id) {
                    $memberId = $member.AdditionalProperties.id
                } elseif ($member -is [string]) {
                    $memberId = $member
                }
                
                Write-Verbose "Checking UAMI member ID: '$memberId' against target: '$($uami.PrincipalId)'"
                
                if ($memberId -and ($memberId -eq $uami.PrincipalId)) {
                    $uamiAlreadyHasRole = $true
                    Write-Host "  ✓ Windows UAMI service principal already has 'Global Administrator'" -ForegroundColor Yellow
                    break
                }
            }
        }
    } catch {
        Write-Verbose "Could not retrieve existing Global Administrator role members: $($_.Exception.Message)"
    }
    
    # Only assign if not already a member
    if (-not $uamiAlreadyHasRole) {
        try {
            Write-Host "  Assigning Global Administrator to Windows UAMI service principal..." -ForegroundColor Gray
            
            # Double-check with a fresh query just before assignment to catch timing issues
            $recentMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -ErrorAction SilentlyContinue
            $doubleCheckMember = $recentMembers | Where-Object { 
                $_.Id -eq $uami.PrincipalId -or 
                $_.ObjectId -eq $uami.PrincipalId -or 
                ($_.AdditionalProperties -and ($_.AdditionalProperties.id -eq $uami.PrincipalId -or $_.AdditionalProperties.objectId -eq $uami.PrincipalId))
            }
            
            if ($doubleCheckMember) {
                Write-Host "  ✓ Windows UAMI service principal already has 'Global Administrator' (found in double-check)" -ForegroundColor Yellow
            } else {
                New-MgDirectoryRoleMemberByRef -DirectoryRoleId $gaRole.Id -BodyParameter @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($uami.PrincipalId)" } | Out-Null
                Write-Host "  ✓ Granted 'Global Administrator' to Windows UAMI service principal ($($uami.PrincipalId))" -ForegroundColor DarkGreen
            }
        } catch {
            if ($_.Exception.Message -like "*One or more added object references already exist*" -or $_.Exception.Message -like "*already exist*") {
                Write-Host "  ✓ Windows UAMI service principal already has 'Global Administrator' (detected during assignment)" -ForegroundColor Yellow
            } else {
                Write-Warning "Failed to grant 'Global Administrator' to Windows UAMI service principal: $($_.Exception.Message)"
                Write-Host "  This may not affect the lab functionality - continuing..." -ForegroundColor Yellow
            }
        }
    }
} catch {
    Write-Warning "Failed to process Global Administrator role assignment for Windows UAMI service principal: $($_.Exception.Message)"
}

# Create a standalone user-assigned managed identity (not attached) with subscription Owner
$orphanUamiName = "xintra-owner-uami"
$orphanUami = Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $orphanUamiName -ErrorAction SilentlyContinue
if (-not $orphanUami) {
    Write-Host "Creating user-assigned managed identity: $orphanUamiName" -ForegroundColor Cyan
    $orphanUami = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $orphanUamiName -Location $AzureLocation
}
try {
    New-AzRoleAssignment -ObjectId $orphanUami.PrincipalId -RoleDefinitionName "Owner" -Scope "/subscriptions/$subId" -ErrorAction Stop | Out-Null
    Write-Host "Granted 'Owner' on subscription to identity: $orphanUamiName" -ForegroundColor DarkGreen
} catch {
    if ($_.Exception.Message -notmatch 'already exists') {
        Write-Warning "Failed to assign Owner to $orphanUamiName : $_"
    }
}

# Give Demo user 1 Contributor on the dormant user-assigned managed identity
$demo1Upn = "demo1@$domain"
try {
    $demo1 = Get-MgUser -UserId $demo1Upn -ErrorAction Stop
    try {
        New-AzRoleAssignment -ObjectId $demo1.Id -RoleDefinitionName "Contributor" -Scope $orphanUami.Id -ErrorAction Stop | Out-Null
        Write-Host "Granted 'Contributor' on $orphanUamiName to $demo1Upn" -ForegroundColor DarkGreen
    } catch {
        if ($_.Exception.Message -notmatch 'already exists') {
            Write-Warning "Failed to grant 'Contributor' on $orphanUamiName to ${demo1Upn}: $($_.Exception.Message)"
        }
    }
} catch {
    Write-Warning "Could not resolve Demo user 1 ($demo1Upn). Skipping RBAC on dormant identity."
}

# Exports
$csvPath = Join-Path -Path $PSScriptRoot -ChildPath "created-users.csv"
$createdOutput | Export-Csv -Path $csvPath -NoTypeInformation

$groupsCsvPath = Join-Path -Path $PSScriptRoot -ChildPath "created-groups.csv"
$groupResults | Export-Csv -Path $groupsCsvPath -NoTypeInformation

$appsCsvPath = Join-Path -Path $PSScriptRoot -ChildPath "created-apps.csv"
$appResults | Export-Csv -Path $appsCsvPath -NoTypeInformation

# Export storage account details including SAS token
if ($global:StorageAccountSas) {
    $storageCsvPath = Join-Path -Path $PSScriptRoot -ChildPath "storage-access-details.csv"
    $storageAccessObj = New-Object PSObject -Property $global:StorageAccountSas
    $storageAccessObj | Export-Csv -Path $storageCsvPath -NoTypeInformation
    Write-Host "Storage access details: $storageCsvPath" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Done. Created/ensured users, security groups, enterprise apps, Azure resources, network, VMs, identities, and RBAC." -ForegroundColor Cyan
Write-Host "User credentials (new accounts): $csvPath" -ForegroundColor Cyan
Write-Host "Group details: $groupsCsvPath" -ForegroundColor Cyan
Write-Host "Enterprise apps: $appsCsvPath" -ForegroundColor Cyan

# Display critical security information
Write-Host "`n=== CRITICAL SECURITY INFORMATION ===" -ForegroundColor Red
Write-Host "This lab contains intentional security flaws for training purposes:" -ForegroundColor Yellow

# Show enterprise app secrets
foreach ($app in $appResults) {
    if ($app.Secret -and $app.CreatedNow) {
        Write-Host "`nEnterprise App: $($app.DisplayName)" -ForegroundColor Cyan
        Write-Host "  App ID: $($app.AppId)" -ForegroundColor White
        Write-Host "  Client Secret: $($app.Secret)" -ForegroundColor Red
        Write-Host "  Tenant ID: $($app.TenantId)" -ForegroundColor White
    }
}

# Show storage account SAS if available
if ($global:StorageAccountSas) {
    Write-Host "`nStorage Account SAS Token:" -ForegroundColor Cyan
    Write-Host "  Account: $($global:StorageAccountSas.StorageAccountName)" -ForegroundColor White
    Write-Host "  SAS Token: $($global:StorageAccountSas.SasToken)" -ForegroundColor Red
    Write-Host "  Expires: $($global:StorageAccountSas.Expiry)" -ForegroundColor White
    Write-Host "  Permissions: $($global:StorageAccountSas.Permissions)" -ForegroundColor White
}

Write-Host "`n=== END CRITICAL INFORMATION ===" -ForegroundColor Red








