# Setup Environment Scripts

This folder contains scripts to automate the setup of demo users and license groups in your Microsoft 365 tenant.

## Prerequisites

These scripts require the following PowerShell modules:

- `Microsoft.Graph.Users`
- `Microsoft.Graph.Identity.DirectoryManagement`
- `Microsoft.Graph.Groups`

You can install them using the following command:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Permissions

You must have sufficient Microsoft 365 admin permissions to run these scripts:

- **Create-DemoUsers.ps1**: Requires the **User administrator** or **Global administrator** role to create users. Assigning the Global Administrator role to a user requires you to be a **Privileged Role Administrator** or **Global administrator**.
- **Create-LicenseGroups.ps1**: Requires the **Groups administrator** or **Global administrator** role to create groups and assign users to groups.

## Scripts

### 1. Create-DemoUsers.ps1

- Creates 5 demo users in your tenant (one admin, four standard users).
- UserPrincipalNames are generated dynamically based on your tenant domain.
- The admin user is assigned the Global Administrator role.
- Passwords are randomly generated and displayed in the console.

**Usage:**
```powershell
.\Create-DemoUsers.ps1
```

### 2. Create-LicenseGroups.ps1

- Creates security groups for licenses: `License-E3`, `License-P2`, and `License-E5`.
- Assigns all users in the tenant to each of these groups.

**Usage:**
```powershell
.\Create-LicenseGroups.ps1
```
