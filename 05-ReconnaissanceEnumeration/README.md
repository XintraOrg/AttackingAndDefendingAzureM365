# Reconnaissance & Enumeration Automation

This folder contains scripts to automate the creation of Access Packages and catalogs in Microsoft Entra ID (Azure AD).

## Scripts

### Create-AccessPackage.ps1

This PowerShell script automates the creation of an Access Package in Microsoft Entra ID (Azure AD) using Microsoft Graph. It also adds all present enterprise applications as resources to the package with default access.

#### Usage

```powershell
# Run the script in PowerShell
.\Create-AccessPackage.ps1
```

You will be prompted to sign in with an account that has the necessary permissions.

#### Prerequisites

- Microsoft.Graph PowerShell module installed
- EntitlementManagement.ReadWrite.All permission
- Identity Governance Administrator or Global Administrator role

#### What the script does

1. Connects to Microsoft Graph with the required permissions.
2. Checks for a writable Access Package Catalog, or creates one if none exists.
3. Creates a new Access Package in the catalog.
4. Enumerates all enterprise applications (service principals) in the tenant.
5. Adds each application as a resource to the catalog (if not already present).
6. Assigns default access (all roles) for each application to the Access Package.

#### Output

- Access Package and Catalog created (if not present)
- All enterprise applications added as resources to the Access Package

#### Notes

- The script is idempotent regarding catalog creation: it will not create duplicates.
- All enterprise applications present at the time of execution will be added as resources.
- Review and adjust the script as needed for your organization's requirements.