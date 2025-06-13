# xintra-m365-templates

This repository contains PowerShell scripts and ARM templates for automating Microsoft 365 and Azure infrastructure tasks, including identity, security, automation, and monitoring scenarios.

## Needed PowerShell modules

- Az.Accounts
- Az.Resources
- Az.KeyVault
- Az.Automation
- Microsoft.Graph (and submodules: Microsoft.Graph.Groups, Microsoft.Graph.Users, Microsoft.Graph.Applications)

## Folder Overview

- `05-ReconnaissanceEnumeration`: Scripts for creating Access Packages and catalogs in Entra ID.
- `06-InitialAccessTechniques`: Scripts for creating enterprise applications and related initial access techniques.
- `07-CredentialTheft`: Scripts and templates for deploying Key Vaults, Automation Accounts, Log Analytics, and RBAC/diagnostic settings.

Refer to each folder's README for details and usage instructions.