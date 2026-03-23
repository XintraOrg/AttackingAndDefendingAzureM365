# ⚠️ CRITICAL SECURITY WARNING ⚠️

## 🚨 **INTENTIONALLY VULNERABLE LAB ENVIRONMENT** 🚨

**⛔ DO NOT DEPLOY TO PRODUCTION ENVIRONMENTS ⛔**

This repository contains PowerShell scripts that **INTENTIONALLY** deploy **SEVERELY COMPROMISED** Microsoft 365 and Azure resources with **CRITICAL SECURITY FLAWS** for training and educational purposes only.

### **DEPLOYMENT RISKS:**
- **Creates users with weak password policies**
- **Deploys enterprise applications with excessive permissions**  
- **Exposes storage accounts with public access and leaked keys**
- **Creates managed identities with subscription-wide Owner privileges**
- **Deploys VMs exposed to the Internet with weak network security**
- **Implements permissive RBAC assignments**
- **Creates long-lived secrets and SAS tokens (up to 10 years)**

### **⚠️ ONLY USE FOR:**
- Security training and education
- Penetration testing practice
- Attack simulation exercises
- Security assessment demonstrations

### **⚠️ NEVER USE FOR:**
- Production workloads
- Real business data
- Customer environments
- Any environment containing sensitive information

---

# xintra-m365-templates

End-to-end **VULNERABLE** lab deployment for Microsoft 365 and Azure resources using PowerShell (`deployment.ps1`).

## 🚀 **Installation & Setup**

### **Step 1: Install Prerequisites**

**Install PowerShell 7+ (if not already installed):**
```powershell
# Install PowerShell 7+ via winget (Windows 10/11)
winget install Microsoft.PowerShell

# Or download from: https://github.com/PowerShell/PowerShell/releases
```

**Install Required PowerShell Modules:**
```powershell
# IMPORTANT: Run PowerShell as Administrator for system-wide installation
# Or use -Scope CurrentUser if you don't have admin rights

# Method 1: Install individual Az modules (recommended)
Install-Module -Name Az.Accounts -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Az.Resources -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Az.KeyVault -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Az.Automation -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Az.OperationalInsights -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Az.Network -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Az.Compute -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Az.ManagedServiceIdentity -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Az.Storage -Force -AllowClobber -Scope CurrentUser

# Method 2: Install complete Az module (larger download but simpler)
# Install-Module -Name Az -Force -AllowClobber -Scope CurrentUser

# Install Microsoft Graph modules (CRITICAL: Install specific submodules)
Install-Module -Name Microsoft.Graph.Authentication -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Applications -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Users -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Groups -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Identity.Governance -Force -AllowClobber -Scope CurrentUser

# Alternative: Install complete Microsoft Graph module (may cause conflicts)
# Install-Module -Name Microsoft.Graph -Force -AllowClobber -Scope CurrentUser

# Verify installations
Get-Module -ListAvailable Az.Accounts
Get-Module -ListAvailable Microsoft.Graph.Authentication
```

**Install OpenSSH (for SSH key generation):**
```powershell
# Windows 10/11 - Install OpenSSH Client
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Verify ssh-keygen is available
ssh-keygen --help
```

### **Step 2: Authentication Setup**

**Connect to Azure and Microsoft Graph:**
```powershell
# Connect to Azure (browser-based authentication)
Connect-AzAccount

# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All","User.ReadWrite.All","Group.ReadWrite.All","RoleManagement.ReadWrite.Directory","Policy.ReadWrite.ApplicationConfiguration","AppRoleAssignment.ReadWrite.All"

# Verify connections
Get-AzContext
Get-MgContext
```

### **Step 3: Verify Permissions**

Ensure your account has sufficient permissions:
- **Azure:** Subscription Owner or Contributor + User Access Administrator
- **Entra ID:** Global Administrator or equivalent delegated roles
- **Microsoft Graph:** Application.ReadWrite.All, Directory.ReadWrite.All, User.ReadWrite.All

### **Step 4: Troubleshooting Module Issues**

**If you encounter Microsoft Graph module errors:**
```powershell
# Clean up any corrupted Graph modules
Get-Module Microsoft.Graph* -ListAvailable | Uninstall-Module -Force
Remove-Module Microsoft.Graph* -Force -ErrorAction SilentlyContinue

# Clear PowerShell module cache
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\PowerShell\ModuleAnalysisCache" -Force -ErrorAction SilentlyContinue

# Reinstall Graph modules individually
Install-Module -Name Microsoft.Graph.Authentication -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Applications -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Users -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Groups -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Force -AllowClobber -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Identity.Governance -Force -AllowClobber -Scope CurrentUser

# Import modules explicitly
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Applications
Import-Module Microsoft.Graph.Identity.Governance
```

**Alternative: Use Beta versions if stable versions fail:**
```powershell
Install-Module -Name Microsoft.Graph.Beta -Force -AllowClobber -Scope CurrentUser
```

### **Step 5: Deploy the Lab**

**Run the automated deployment:**
```powershell
# Clone repository (if not already done)
git clone https://github.com/ExeqZ/xintra-m365-templates.git
cd xintra-m365-templates

# Run deployment script
.\deployment.ps1 `
  -AzureLocation westeurope `
  -ResourceGroupName default `
  -KeyVaultName xintrakey `
  -AutomationAccountName xintraautomation `
  -LogAnalyticsWorkspaceName xintralog
```

### **Step 6: Complete Manual Configuration**

**⚠️ IMPORTANT:** The following steps must be completed manually after running the deployment script:

#### **🔐 Entra ID Role Assignments**
1. **Assign 'Maintain User' app to User Administrator role:**
   - Navigate to Entra ID > Enterprise Applications > "Maintain User"
   - Go to Permissions > Admin consent > Grant admin consent
   - Go to App roles > Assign users and groups > Add User Administrator role

2. **Grant 'Global Administrator' to Windows UAMI service principal:**
   - Navigate to Entra ID > Roles and administrators > Global Administrator
   - Add assignments > Select the Windows VM user-assigned managed identity
   - Complete assignment (⚠️ CRITICAL VULNERABILITY - for training only)

#### **🏢 Azure Resource Assignments**
3. **Assign 'Contributor' to SP 'xintra contributor app':**
   - Navigate to Azure Portal > Subscriptions > Your subscription > Access control (IAM)
   - Add > Add role assignment > Contributor
   - Select the "xintra contributor app" service principal
   - Complete assignment

4. **Assign 'Owner' to xintra-owner-uami:**
   - Navigate to Azure Portal > Subscriptions > Your subscription > Access control (IAM)
   - Add > Add role assignment > Owner
   - Select the "xintra-owner-uami" managed identity
   - Complete assignment (⚠️ Creates dormant high-privilege identity)

5. **Manually grant yourself 'Key Vault Secrets Officer':**
   - Navigate to the created Key Vault > Access control (IAM)
   - Add > Add role assignment > Key Vault Secrets Officer
   - Select your user account
   - Complete assignment

#### **📦 Resource Creation**
6. **Create Access Package:**
   - Navigate to Entra ID > Identity Governance > Access packages
   - Create new catalog: "xintra access"
   - Create access package with auto-approval and permanent access
   - Link to "Maintain User" application

7. **Create Automation Account:**
   - Navigate to Azure Portal > Create a resource > Automation Account
   - Name: `xintraautomation` (or as specified in deployment)
   - Configure with system-assigned managed identity
   - Add any required runbooks or credentials

8. **Create public container in storage account:**
   - Navigate to the created storage account > Containers
   - Create container named "public"
   - Set public access level to "Container"
   - Upload the generated access key file to this container

#### **🔑 Key Vault Secrets**
9. **Create Key Vault secrets:**
   - Navigate to the Key Vault > Secrets
   - Create secrets for:
     - SSH private/public keys (generated during deployment)
     - Application client secrets
     - Any additional sensitive configuration

#### **📋 Microsoft 365 License Assignment**
10. **Start trial licenses and assign to license groups:**
    - Navigate to Microsoft 365 Admin Center > Billing > Purchase services
    - Start free trials for:
      - **Microsoft 365 E3** (if available)
      - **Microsoft 365 E5** (recommended for advanced security features)
      - **Microsoft 365 EntraID P2** 
    - Navigate to Microsoft 365 Admin Center > Billing > Licenses
    - For each activated license:
      - Select the license type
      - Click "Assign licenses"
      - Choose "Assign to a group"
      - Select corresponding license group:
        - `lic-m365-e3` → Microsoft 365 E3 licenses
        - `lic-m365-e5` → Microsoft 365 E5 licenses  
        - `lic-m365-p2` → Microsoft EntraID P2 licenses
      - Enable all available services for maximum attack surface
      - Complete assignment

**⚠️ License Note:** Trial licenses typically last 30 days and provide full functionality for lab testing. Group-based licensing automatically assigns licenses to users added to these groups.

**⚠️ Security Note:** These manual steps introduce intentional vulnerabilities for training purposes. Never implement these configurations in production environments.

## What deployment.ps1 Creates

### **🔐 Identity (Entra ID)**

**Users Created:**
- **4 Administrative Users:** global.admin, cloudapp.admin, user.admin, privilegedrole.admin
- **5 Demo Users:** demo1, demo2, demo3, demo4, demo5
- All users assigned to license groups: `lic-m365-e3`, `lic-m365-P2`, `lic-m365-e5`

**Security Groups:**
- **17 Permission Groups** for resource-level access control:
  - Key Vault: `perm-xintrakey-*` (reader, contributor, owner)
  - Automation: `perm-xintraautomation-*` (reader, contributor, owner) 
  - Log Analytics: `perm-xintralog-*` (reader, contributor, owner)
  - Storage: `perm-xintrastore-*` (reader, contributor, owner)
  - Legacy: `KeyVault-Secrets-Reader`, `KeyVault-AccessPolicy-Admin`

**Enterprise Applications:**
- **"Office.Read"** - Multitenant app with client secret
- **"Maintain User"** - Multitenant app with User Administrator role
- **"evil automation account"** - Single-tenant app with dangerous Graph permissions
- **"xintra contributor app"** - App with subscription Contributor access assigned to ALL users

### **☁️ Azure Resources (Resource Group: "default")**

**Core Infrastructure:**
- **Key Vault** (`xintrakey`) - Stores secrets including SSH keys and sensitive data
- **Automation Account** (`xintraautomation`) - Contains stored credentials
- **Log Analytics Workspace** (`xintralog`) - Centralized logging with diagnostic settings
- **Storage Account** (`xintrastorage`) - **SEVERELY MISCONFIGURED** (see security flaws below)

**Network & Compute:**
- **Virtual Network** (`xintra-vnet`) with single subnet and permissive NSG rules
- **Linux VM** (`xintra-ubuntu`) - Ubuntu 22.04 with system-assigned identity
- **Windows VM** (`xintra-win11`) - Windows 11 22H2 with Azure CLI pre-installed
- **Public IP addresses** for both VMs exposed to Internet
- **Azure AD Login extensions** enabled on both VMs

**Managed Identities:**
- **System-assigned identities** on both VMs with Key Vault access
- **User-assigned identity** (`xintra-win11-uami`) attached to Windows VM with subscription Owner
- **Orphaned user-assigned identity** (`xintra-owner-uami`) with subscription Owner (not attached to any resource)

## 🔴 **CRITICAL SECURITY FLAWS** (Intentional)

### **1. Storage Account - Worst-Case Misconfiguration**
**⚠️ Flaws:**
- **Public anonymous access** enabled (container-level)
- **HTTP traffic allowed** (HTTPS not enforced)
- **10-year SAS token** with full permissions (`racwdl`)
- **Access key leaked** inside the same storage account (`public/access-key.txt`)
- **No network restrictions** (firewall allows all)

**🎯 Attack Examples:**
# Anonymous access to public container
# Download leaked access key
# Use SAS token for full access


### **2. Enterprise App "evil automation account"**
**⚠️ Flaws:**
- **5-year client secret** validity
- **Dangerous Graph permissions:**
  - `Directory.ReadWrite.All` - Full directory access
  - `User.ReadWrite.All` - Create/modify any user
  - `DeviceManagement*.ReadWrite.All` - Full device control

**🎯 Attack Examples:**
# Authenticate as application
# Create backdoor global admin

### **3. Enterprise App "xintra contributor app"** 
**⚠️ Flaws:**
- **Subscription Contributor** permissions
- **Assigned to ALL Member users** in tenant
- Client secret accessible to all assigned users

**🎯 Attack Examples:**
# Any user can abuse app credentials for subscription access


### **4. Dormant User-Assigned Managed Identity**
**⚠️ Flaws:**
- **Subscription Owner permissions** on unused identity
- **Demo1 has Contributor** on the identity resource
- Can be attached to any resource Demo1 can create

**🎯 Attack Examples:**
# Demo1 creates VM and attaches powerful identity
# From VM, get Owner-level access token


### **5. Key Vault Exposure**
**⚠️ Flaws:**
- **Demo2 and Demo3** have `Key Vault Secrets User` access
- **SSH private keys** stored as secrets
- **Sensitive application secrets** accessible

**🎯 Attack Examples:**
# Extract SSH private key
# SSH to Linux VM


### **6. Network Security**
**⚠️ Flaws:**
- **SSH (22) and RDP (3389)** open to Internet (`0.0.0.0/0`)
- **No additional network protection**
- Public IP addresses on both VMs


### **7. Windows VM with Excessive Privileges**
**⚠️ Flaws:**
- **User-assigned identity** has subscription Owner
- **System-assigned identity** has Global Administrator
- **Azure CLI pre-installed**

**🎯 Attack Examples:**
# From Windows VM, authenticate with managed identity
# Full subscription and tenant control


## Prerequisites

- **PowerShell 7+** recommended
- **Modules:** Az.Accounts, Az.Resources, Az.KeyVault, Az.Automation, Az.OperationalInsights, Az.Network, Az.Compute, Az.ManagedServiceIdentity, Az.Storage, Microsoft.Graph
- **OpenSSH** (ssh-keygen) available in PATH
- **Sufficient Azure/Entra permissions** to create and assign resources/roles

## Quick start

```powershell
# From repo root
.\deployment.ps1 `
  -AzureLocation westeurope `
  -ResourceGroupName default `
  -KeyVaultName xintrakey `
  -AutomationAccountName xintraautomation `
  -LogAnalyticsWorkspaceName xintralog
```

## Cleanup

### **⚠️ CRITICAL WARNING**
The cleanup process is **DESTRUCTIVE** and will permanently delete all lab resources. Ensure you have backups of any important data before proceeding.

### **Quick Start Commands**

```powershell
# Preview what would be removed (SAFE - recommended first)
.\cleanup.ps1 -WhatIf

# Interactive cleanup with confirmation prompts
.\cleanup.ps1

# Force removal without confirmation prompts (DANGER!)
.\cleanup.ps1 -Force
```

### **🤖 Automatic Cleanup Steps**

The `cleanup.ps1` script automatically handles the following resources:

#### **1. Regular Demo Users** ✅
- **Automatically removes:** `demo1@domain` through `demo5@domain`
- **Includes:** Full role assignment cleanup before user deletion
- **Handles:** Directory roles, PIM eligible roles, active PIM assignments

#### **2. Security Groups** ✅
- **License groups:** `lic-m365-e3`, `lic-m365-P2`, `lic-m365-e5`
- **Permission groups:** All `perm-xintra*` groups (Key Vault, Automation, Log Analytics, Storage)
- **Legacy groups:** `KeyVault-Secrets-Reader`, `KeyVault-AccessPolicy-Admin`
- **Smart license handling:** Automatically removes license assignments before group deletion

#### **3. Enterprise Applications** ✅
- **Removes:** `Office.Read`, `Maintain User`, `evil automation account`, `xintra contributor app`
- **Cleanup order:** Service principals first, then applications
- **Verification:** Checks existence before each deletion attempt

#### **4. Azure Resources** ✅
- **Complete resource group deletion:** Removes entire `default` resource group
- **Includes all resources:** VMs, storage accounts, Key Vault, networking, managed identities
- **Warning:** This operation can take several minutes

#### **5. Generated Files** ✅
- **CSV files:** `created-users.csv`, `created-groups.csv`, `created-apps.csv`, `storage-access-details.csv`
- **Secure deletion:** Removes sensitive credential files from local system

### **👤 Manual Cleanup Required**

**⚠️ IMPORTANT:** The following resources require manual cleanup due to elevated privileges and security implications:

#### **🔐 Administrative User Accounts**
**Manual deletion required for safety:**

```powershell
# These users are EXCLUDED from automatic cleanup
# Navigate to Entra ID > Users for manual deletion
```

**Users requiring manual cleanup:**
- **`global.admin@domain`** 
  - ⚠️ **Global Administrator privileges**
  - **Steps:** Remove all role assignments → Delete user
- **`cloudapp.admin@domain`**
  - ⚠️ **Cloud Application Administrator privileges** 
  - **Steps:** Remove all role assignments → Delete user
- **`user.admin@domain`**
  - ⚠️ **User Administrator privileges**
  - **Steps:** Remove all role assignments → Delete user
- **`privilegedrole.admin@domain`**
  - ⚠️ **Privileged Role Administrator privileges**
  - **Steps:** Remove all role assignments → Delete user

#### **🔐 Entra ID Role Assignments**
**Manual removal required:**
1. **'User Administrator' role from 'Maintain User' app**
   - Navigate: Entra ID > Enterprise Applications > 'Maintain User' > App roles
   - Action: Remove User Administrator role assignment

2. **'Global Administrator' role from Windows UAMI**
   - Navigate: Entra ID > Roles and administrators > Global Administrator  
   - Action: Find and remove Windows VM managed identity assignment

#### **🏢 Azure Subscription Role Assignments**
**Manual removal required:**
1. **'Contributor' role from 'xintra contributor app'**
   - Navigate: Azure Portal > Subscriptions > Access control (IAM)
   - Action: Remove Contributor role assignment

2. **'Owner' role from 'xintra-owner-uami'**
   - Navigate: Azure Portal > Subscriptions > Access control (IAM)
   - Action: Remove Owner role assignment

#### **📦 Access Packages (if created manually)**
**Manual removal required:**
1. **'xintra access' access package**
   - Navigate: Entra ID > Identity Governance > Access packages
   - Action: Delete access package

2. **'xintra access' catalog**
   - Navigate: Entra ID > Identity Governance > Catalogs
   - Action: Delete catalog

#### **🔑 Key Vault Permissions**
**Manual removal required:**
- **Manual 'Key Vault Secrets Officer' role assignments**
  - Navigate: Key Vault > Access control (IAM)
  - Action: Remove manually assigned permissions

#### **⚙️ Automation Account (if created manually)**
**Manual removal required:**
- Navigate: Azure Portal > Automation Accounts
- Action: Delete manually created automation account

### **📋 Cleanup Verification**

After running the cleanup script, verify the following:

**✅ Automatic Cleanup Verification:**
- [ ] Demo users (demo1-demo5) are deleted
- [ ] All security groups are removed
- [ ] Enterprise applications are deleted
- [ ] Azure resource group is deleted
- [ ] CSV files are removed from local system

**✅ Manual Cleanup Verification:**
- [ ] Admin users are manually deleted
- [ ] All role assignments are removed
- [ ] Access packages are deleted (if created)
- [ ] Subscription-level role assignments are cleaned up

### **🚨 Troubleshooting Common Issues**

**Problem:** "Group with active licenses assigned cannot be deleted"
```powershell
# The script handles this automatically, but if it fails:
# Navigate to Microsoft 365 Admin Center > Active users > Licenses
# Remove license assignments from groups manually
```

**Problem:** "Insufficient privileges to delete user"
```powershell
# This is expected for admin users - they require manual deletion
# Check Entra ID > Users > [user] > Assigned roles
# Remove all role assignments first, then delete
```

**Problem:** "Application has role assignments"
```powershell
# The script handles this automatically by removing service principals first
# If manual intervention needed: Entra ID > Enterprise applications > [app] > Users and groups
```

### **🔄 Complete Lab Reset**

For a complete lab reset:

```powershell
# Step 1: Run automatic cleanup
.\cleanup.ps1 -Force

# Step 2: Complete manual cleanup (see manual steps above)

# Step 3: Re-run deployment
.\deployment.ps1 -AzureLocation westeurope -ResourceGroupName default
```

**⚠️ Security Note:** Always verify complete cleanup in production-adjacent environments. Orphaned resources with elevated privileges pose ongoing security risks.

## Generated Files

After deployment, the following files contain sensitive information:
- `created-users.csv` - User credentials and temporary passwords
- `created-groups.csv` - Security group details
- `created-apps.csv` - Enterprise application secrets
- `storage-access-details.csv` - Storage account SAS tokens and keys

**⚠️ Secure these files appropriately - they contain production-equivalent secrets!**


## 🛡️ **TRAINING USE ONLY**

This environment is designed for:
- **Red team exercises**
- **Security awareness training**
- **Incident response practice** 
- **Detection engineering**
- **Penetration testing education**

**Remember:** These are intentional vulnerabilities for learning. In production environments, implement proper security controls, follow least privilege principles, and regularly audit permissions.
