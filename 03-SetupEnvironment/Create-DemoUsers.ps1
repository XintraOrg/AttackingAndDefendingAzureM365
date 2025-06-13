# Requires: Microsoft.Graph PowerShell module
# Permissions: User administrator or Global administrator to create users.
#              Privileged Role Administrator or Global administrator to assign admin roles.
# This script creates 5 demo users with secure random passwords using Microsoft Graph.

Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.DirectoryManagement

function New-SecurePassword {
    Add-Type -AssemblyName System.Web
    [System.Web.Security.Membership]::GeneratePassword(16,3)
}

# Connect to Microsoft Graph (interactive login)
Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

# Get the default tenant domain
$tenantDomain = (Get-MgDomain | Where-Object { $_.IsDefault -eq $true }).Id
if (-not $tenantDomain) {
    Write-Error "Could not determine the default tenant domain."
    exit 1
}

$users = @(
    @{ Alias = "admin.as"; DisplayName = "Admin Aaron Star"; Role = "Admin" },
    @{ Alias = "ab"; DisplayName = "Alice Backer"; Role = "User" },
    @{ Alias = "bc"; DisplayName = "Bob Christner"; Role = "User" },
    @{ Alias = "llm"; DisplayName = "Linda Laurel Miller"; Role = "User" },
    @{ Alias = "ef"; DisplayName = "Eve Ferris"; Role = "User" }
)

foreach ($user in $users) {
    $userPrincipalName = "$($user.Alias)@$tenantDomain"
    $password = New-SecurePassword
    Write-Host "Creating user: $($user.DisplayName) ($userPrincipalName)"

    $nameParts = $user.DisplayName.Split(" ")
    $firstName = $nameParts[0]
    $lastName = $nameParts[-1]

    $userParams = @{
        AccountEnabled = $true
        DisplayName = $user.DisplayName
        MailNickname = $user.Alias
        UserPrincipalName = $userPrincipalName
        PasswordProfile = @{
            Password = $password
            ForceChangePasswordNextSignIn = $false
        }
        GivenName = $firstName
        Surname = $lastName
    }

    try {
        New-MgUser @userParams
        Write-Host "User: $userPrincipalName Password: $password"
    } catch {
        Write-Host "Failed to create user $userPrincipalName: $_"
    }

    if ($user.Role -eq "Admin") {
        # Assign Global Administrator role
        $role = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }
        if (-not $role) {
            Enable-MgDirectoryRole -DirectoryRoleTemplateId "62e90394-69f5-4237-9190-012177145e10"
            $role = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }
        }
        $createdUser = Get-MgUser -UserId $userPrincipalName
        if ($role -and $createdUser) {
            Add-MgDirectoryRoleMember -DirectoryRoleId $role.Id -BodyParameter @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($createdUser.Id)"
            }
            Write-Host "Assigned Global Admin role to $userPrincipalName"
        }
    }
}
