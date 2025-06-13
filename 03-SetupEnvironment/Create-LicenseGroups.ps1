# Requires: Microsoft.Graph PowerShell module
# Permissions: Groups administrator or Global administrator to create groups and assign users.
# This script creates license security groups and assigns all users to them.

Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Users

# Connect to Microsoft Graph (interactive login)
Connect-MgGraph -Scopes "Group.ReadWrite.All", "User.Read.All"

$licenseNames = @("E3", "P2", "E5")
$createdGroups = @{}

foreach ($license in $licenseNames) {
    $groupName = "License-$license"
    $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ConsistencyLevel eventual
    if ($group) {
        # If multiple groups found, take the first one
        if ($group -is [array]) {
            $group = $group[0]
        }
        Write-Host "Group already exists: $groupName"
        $createdGroups[$license] = $group.Id
    } else {
        $newGroup = New-MgGroup -DisplayName $groupName `
            -MailEnabled $false `
            -MailNickname $($groupName.ToLower()) `
            -SecurityEnabled $true `
            -GroupTypes @()
        Write-Host "Created group: $groupName"
        $createdGroups[$license] = $newGroup.Id
    }
}

# Get all users (excluding guests)
$users = Get-MgUser -Filter "userType eq 'Member'" -All

foreach ($user in $users) {
    foreach ($groupId in $createdGroups.Values) {
        try {
            Add-MgGroupMember -GroupId $groupId -DirectoryObjectId $user.Id -ErrorAction Stop
            Write-Host "Added $($user.UserPrincipalName) to group $groupId"
        } catch {
            if ($_.Exception.Message -notlike "*added object references already exist*") {
                Write-Host "Failed to add $($user.UserPrincipalName) to group $groupId: $_"
            }
        }
    }
}
