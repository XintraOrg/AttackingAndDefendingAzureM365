# Initial Access Techniques

This folder contains scripts for simulating and automating initial access scenarios in Azure AD and Microsoft 365.

## To automate

- Install a Hybrid Exchange server  
  https://www.xintra.org/dashboard/training/course/1/page/70

- Create Azure AD B2C tenant

## Scripts

### Create-EvilEnterpriseApp.ps1

Creates a multitenant Azure AD enterprise application named "Office.Read" with a web redirect URI (`http://localhost:5000/getAToken`), generates a client secret, and outputs the client ID, client secret, and tenant ID.

#### Usage

```powershell
.\Create-EvilEnterpriseApp.ps1
```

#### Prerequisites

- Microsoft.Graph PowerShell module installed
- Application Administrator or Global Administrator permissions

#### Output

- Application registration and service principal created
- Client ID, client secret, and tenant ID displayed for use in authentication scenarios