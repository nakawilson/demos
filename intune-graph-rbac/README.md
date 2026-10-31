# Intune + Microsoft Graph — OAuth / RBAC Demo (PowerShell)

Demonstrates OAuth 2.0 against Microsoft Graph to access Intune RBAC-protected
resources, using raw REST (no Microsoft Graph SDK required) so you can see
exactly what OAuth and Intune RBAC are doing.

## What it does

1. Acquires an access token — client credentials (app-only, secret or
   certificate) or device code (delegated, interactive sign-in).
2. Decodes the JWT payload to show `scp` (delegated scopes) vs `roles`
   (application permissions), `aud`, `appid` / `oid`, and expiry — without
   printing the token itself.
3. Calls Intune endpoints under `/deviceManagement`: managed devices,
   device compliance policies, Intune RBAC role definitions, and role
   assignments, with pagination and 429 retry handling.
4. Optionally tests a privileged write (`syncDevice`) with
   `-TryPrivilegedWrite` — off by default.

## The key lesson

Graph permission ≠ Intune access. There are two gates:

- **Gate 1 — Entra ID / Graph:** the token must contain the right scope/role,
  e.g. `DeviceManagementManagedDevices.Read.All`, and admin consent must have
  been granted for application permissions.
- **Gate 2 — Intune RBAC:** for a delegated token, the signed-in user must
  also have an Intune role assignment (e.g. Intune Administrator, Read Only
  Operator, Help Desk Operator) covering the target devices/users. For an
  app-only token, the service principal must likewise be given an Intune role
  assignment. Otherwise Graph returns 403 even though the token looks correct.

## Prerequisites

Entra app registration (once, in Entra ID):

1. App registrations > New registration, single tenant.
2. API permissions > Microsoft Graph:
   - Application (client credentials): `DeviceManagementManagedDevices.Read.All`,
     `DeviceManagementConfiguration.Read.All`, `DeviceManagementRBAC.Read.All`
   - Delegated (device code): same three, plus `User.Read`
3. Grant admin consent for the tenant.
4. Certificates & secrets: a short-lived secret, or upload a certificate
   (preferred for unattended use).
5. Intune RBAC: Intune admin center > Tenant administration > Roles — assign
   a role to the user (delegated) or the service principal (app-only).
   Start with Read Only Operator.

Requires PowerShell 5.1+ / 7+. No modules required.

## Run

```powershell
# App-only with a secret from an environment variable
$s = ConvertTo-SecureString $env:INTUNE_DEMO_CLIENT_SECRET -AsPlainText -Force
.\Intune-Graph-RBAC-Demo.ps1 -TenantId $env:INTUNE_DEMO_TENANT_ID `
  -ClientId $env:INTUNE_DEMO_CLIENT_ID -AuthMode ClientCredentials -ClientSecret $s

# App-only with a certificate (preferred)
.\Intune-Graph-RBAC-Demo.ps1 -TenantId "<tenant-id>" -ClientId "<app-id>" `
  -AuthMode ClientCredentials -CertificateThumbprint "<thumbprint>"

# Delegated — your Intune RBAC applies
.\Intune-Graph-RBAC-Demo.ps1 -TenantId "<tenant-id>" -ClientId "<app-id>" `
  -AuthMode DeviceCode -ExportCsv "$env:TEMP\IntuneDevices.csv" -TryPrivilegedWrite
```

## Try next

- Re-run with `-AuthMode DeviceCode` as a user with no Intune role: expect 403.
- Grant that user Read Only Operator and re-run: the read should succeed.
- Re-run with `-TryPrivilegedWrite` as that read-only user: expect 403 on the write.
- Compare the token claims between the two auth modes: `scp` (delegated) vs `roles` (app-only).

## Security

Never hard-code a client secret in this script. Pass it as a `SecureString`,
an environment variable, or use a certificate. Tokens are kept in memory only
and are never written to the console or to disk.
