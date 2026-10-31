<#
.SYNOPSIS
    Demonstrates OAuth 2.0 against Microsoft Graph to access Intune RBAC-protected resources.

.DESCRIPTION
    Raw REST demo (no Microsoft.Graph SDK required) so you can see exactly what
    OAuth and Intune RBAC are doing:

      1. Acquire an access token - client credentials (app-only) OR device code (delegated)
      2. Decode the JWT (header/payload only, no signature validation) to show
         `scp` (delegated scopes) vs `roles` (app permissions), `aud`, `appid`/`oid`
      3. Call Intune endpoints under /deviceManagement and show pagination + 403 handling
      4. List the Intune RBAC role definitions / assignments that gate those calls

    The key lesson this script is built to prove:
      Graph permission != Intune access. There are TWO gates.

        Gate 1 - Entra ID / Graph: the token must contain the right scope/role,
                 e.g. DeviceManagementManagedDevices.Read.All, and admin consent
                 must have been granted for application permissions.
        Gate 2 - Intune RBAC: for a delegated token, the signed-in user must also
                 have an Intune role assignment (e.g. Intune Administrator,
                 Read Only Operator, Help Desk Operator) with a scope that covers
                 the target devices/users. For an app-only token, the service
                 principal must likewise be given an Intune role assignment -
                 Intune admin center > Tenant administration > Roles - otherwise
                 Graph returns 403 even though the token looks correct.

    If a call returns 403, this script prints both checks to run instead of
    guessing which gate failed.

.NOTES
    Author      : Wai - demo script
    Requires    : PowerShell 5.1+ / 7+, internet access to login.microsoftonline.com
                  and graph.microsoft.com. No modules required.
    Security    : Never hard-code a client secret in this file. Pass it as a
                  SecureString, an environment variable, or use a certificate.
                  Tokens are kept in memory only and are never written to the
                  console or to disk. The JWT decode below prints claims only -
                  never print $AccessToken itself.

.PREREQUISITES - Entra app registration (do once, in Entra ID / Azure portal)
    1. App registrations > New registration > single tenant, no redirect URI
       needed for client credentials; for device-code flow add the public-client
       redirect URI https://login.microsoftonline.com/common/oauth2/nativeclient
       and enable "Allow public client flows" if prompted.
    2. API permissions > Microsoft Graph > add these (least privilege for the demo):
         Application (for -AuthMode ClientCredentials):
           DeviceManagementManagedDevices.Read.All
           DeviceManagementConfiguration.Read.All
           DeviceManagementRBAC.Read.All
         Delegated (for -AuthMode DeviceCode):
           DeviceManagementManagedDevices.Read.All
           DeviceManagementConfiguration.Read.All
           DeviceManagementRBAC.Read.All
           User.Read
    3. Grant admin consent for the tenant (required for application permissions).
    4. Certificates & secrets: create a secret (short-lived, rotate it) OR
       upload a certificate. Certificate auth is preferred for unattended use.
    5. Intune RBAC: Intune admin center > Tenant administration > Roles >
       assign a role to the user (delegated) or to the service principal
       (app-only). Start with Read Only Operator to prove read access, then
       try Help Desk Operator / Intune Administrator to see the difference.

.EXAMPLE
    # App-only, secret from an environment variable (no secret on disk / in history)
    $s = ConvertTo-SecureString $env:INTUNE_DEMO_CLIENT_SECRET -AsPlainText -Force
    .\Intune-Graph-RBAC-Demo.ps1 -TenantId $env:INTUNE_DEMO_TENANT_ID `
        -ClientId $env:INTUNE_DEMO_CLIENT_ID -AuthMode ClientCredentials `
        -ClientSecret $s

.EXAMPLE
    # App-only, certificate (preferred for automation)
    .\Intune-Graph-RBAC-Demo.ps1 -TenantId "<tenant-id>" -ClientId "<app-id>" `
        -AuthMode ClientCredentials -CertificateThumbprint "<thumbprint>"

.EXAMPLE
    # Delegated - sign in interactively via device code, Intune RBAC of YOUR user applies
    .\Intune-Graph-RBAC-Demo.ps1 -TenantId "<tenant-id>" -ClientId "<app-id>" `
        -AuthMode DeviceCode

.EXAMPLE
    # Delegated + export the device list + attempt a privileged write (sync) on 1 device
    .\Intune-Graph-RBAC-Demo.ps1 -TenantId "<tenant-id>" -ClientId "<app-id>" `
        -AuthMode DeviceCode -ExportCsv "$env:TEMP\IntuneDevices.csv" -TryPrivilegedWrite
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Entra tenant ID (GUID) or verified domain, e.g. contoso.onmicrosoft.com")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true, HelpMessage = "Application (client) ID of the Entra app registration")]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [ValidateSet("ClientCredentials", "DeviceCode")]
    [string]$AuthMode = "ClientCredentials",

    # App-only only: either a secret OR a certificate thumbprint. Certificate wins if both are given.
    [Parameter(Mandatory = $false)]
    [System.Security.SecureString]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [ValidatePattern("^[0-9A-Fa-f]{40}$")]
    [string]$CertificateThumbprint,

    # Delegated only: space-separated scopes. Keep this list to what the demo actually calls.
    [Parameter(Mandatory = $false)]
    [string]$DelegatedScopes = "User.Read DeviceManagementManagedDevices.Read.All DeviceManagementConfiguration.Read.All DeviceManagementRBAC.Read.All",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$Top = 5,

    [Parameter(Mandatory = $false)]
    [string]$ExportCsv,

    # OFF by default. When on, POSTs syncDevice for the first managed device returned.
    # That is a write: it needs DeviceManagementManagedDevices.ReadWrite.All (or
    # .PrivilegedOperations.All) AND an Intune role with "Remote tasks / Sync device".
    # It is the deliberate 403 demo - a read-only user/app will fail here, and should.
    [Parameter(Mandatory = $false)]
    [switch]$TryPrivilegedWrite
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GraphBase = "https://graph.microsoft.com/v1.0"
$TokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$DeviceCodeEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function ConvertTo-Base64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $b64 = [Convert]::ToBase64String($Bytes)
    return $b64.TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function ConvertFrom-Base64Url {
    param([Parameter(Mandatory = $true)][string]$Value)
    $s = $Value.Replace("-", "+").Replace("_", "/")
    switch ($s.Length % 4) { 2 { $s += "==" } 3 { $s += "=" } }
    return [Convert]::FromBase64String($s)
}

function Show-TokenClaims {
    <#
    .SYNOPSIS Decode the JWT payload for DEMO visibility only.
    Never log the raw token. This prints claims (scp/roles/aud/exp) so you can
    prove Gate 1 before calling Graph.
    #>
    param([Parameter(Mandatory = $true)][string]$AccessToken)

    $parts = $AccessToken.Split(".")
    if ($parts.Count -ne 3) { throw "Access token is not a JWT (expected 3 parts)." }

    $payloadJson = [System.Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url -Value $parts[1]))
    $claims = $payloadJson | ConvertFrom-Json

    $expiry = $null
    if ($claims.exp) {
        $expiry = ([DateTimeOffset]::FromUnixTimeSeconds([long]$claims.exp)).LocalDateTime
    }

    Write-Host "`n--- Token claims (payload only, signature NOT validated here) ---" -ForegroundColor Cyan
    Write-Host ("  aud   : {0}" -f $claims.aud)
    Write-Host ("  iss   : {0}" -f $claims.iss)
    Write-Host ("  appid : {0}  (client id the token was issued to)" -f $claims.appid)
    Write-Host ("  oid   : {0}  (object id of user or service principal)" -f $claims.oid)
    if ($claims.upn)         { Write-Host ("  upn   : {0}  (delegated user)" -f $claims.upn) }
    if ($claims.scp)         { Write-Host ("  scp   : {0}  <-- delegated scopes" -f $claims.scp) }
    if ($claims.roles)       { Write-Host ("  roles : {0}  <-- application permissions" -f ($claims.roles -join ", ")) }
    if ($expiry)             { Write-Host ("  exp   : {0} (local time)" -f $expiry) }
    Write-Host "  NOTE: a token can have the right scp/roles and STILL get 403 from"
    Write-Host "        Intune. That is Gate 2 (Intune RBAC) - see the 403 handler below."
    return $claims
}

function Get-ClientAssertionJwt {
    <#
    .SYNOPSIS Build a signed client_assertion JWT for certificate-based OAuth.
    Uses the cert private key from the CurrentUser or LocalMachine store.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )

    $cert = Get-ChildItem "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) { $cert = Get-ChildItem "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue }
    if (-not $cert) { throw "Certificate $Thumbprint not found in CurrentUser\My or LocalMachine\My." }
    if (-not $cert.HasPrivateKey) { throw "Certificate $Thumbprint has no private key - it cannot sign a client assertion." }

    $now = [DateTimeOffset]::UtcNow
    $header = @{ alg = "RS256"; typ = "JWT"; x5t = (ConvertTo-Base64Url -Bytes $cert.GetCertHash()) } | ConvertTo-Json -Compress
    $payload = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        iss = $ClientId; sub = $ClientId
        jti = [Guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds(); iat = $now.ToUnixTimeSeconds()
        exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    $toSign = "{0}.{1}" -f (ConvertTo-Base64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes($header))),
                               (ConvertTo-Base64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes($payload)))
    $rsa = $cert.GetRSAPrivateKey()
    if (-not $rsa) { throw "Certificate $Thumbprint does not expose an RSA private key." }
    $sig = $rsa.SignData(
        [System.Text.Encoding]::UTF8.GetBytes($toSign),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    return "{0}.{1}" -f $toSign, (ConvertTo-Base64Url -Bytes $sig)
}

function Get-ClientCredentialsToken {
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $false)][System.Security.SecureString]$ClientSecret,
        [Parameter(Mandatory = $false)][string]$CertificateThumbprint
    )

    $body = @{
        grant_type = "client_credentials"
        client_id  = $ClientId
        scope      = "https://graph.microsoft.com/.default"
    }

    if ($CertificateThumbprint) {
        Write-Verbose "Using certificate assertion (no secret sent)."
        $body["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        $body["client_assertion"] = Get-ClientAssertionJwt -TenantId $TenantId -ClientId $ClientId -Thumbprint $CertificateThumbprint
    }
    elseif ($ClientSecret) {
        # Convert SecureString -> plain text only for this one POST, then zero it.
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
        try { $body["client_secret"] = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    }
    else {
        throw "ClientCredentials needs -ClientSecret or -CertificateThumbprint. Prefer the certificate."
    }

    Write-Host "Requesting app-only token (grant_type=client_credentials, scope=https://graph.microsoft.com/.default)..." -ForegroundColor Cyan
    $resp = Invoke-RestMethod -Uri $TokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
    if (-not $resp.access_token) { throw "Token endpoint returned no access_token." }
    return $resp.access_token
}

function Get-DeviceCodeToken {
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][string]$Scopes
    )

    $dcBody = @{ client_id = $ClientId; scope = $Scopes }
    $dc = Invoke-RestMethod -Uri $DeviceCodeEndpoint -Method Post -Body $dcBody -ContentType "application/x-www-form-urlencoded"

    Write-Host "`n--- Delegated sign-in (device code flow) ---" -ForegroundColor Yellow
    Write-Host ("  Go to : {0}" -f $dc.verification_uri)
    Write-Host ("  Enter : {0}" -f $dc.user_code)
    Write-Host ("  (code expires in {0} minutes; sign in as a user who has an Intune role)" -f [math]::Round($dc.expires_in / 60))
    Write-Host "  Waiting for sign-in..."

    $deadline = (Get-Date).AddSeconds($dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $dc.interval
        $pollBody = @{
            grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
            client_id   = $ClientId
            device_code = $dc.device_code
        }
        try {
            $resp = Invoke-RestMethod -Uri $TokenEndpoint -Method Post -Body $pollBody -ContentType "application/x-www-form-urlencoded"
            if ($resp.access_token) { return $resp.access_token }
        }
        catch {
            $err = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($err.error -eq "authorization_pending") { continue }
            if ($err.error -eq "slow_down") { Start-Sleep -Seconds 5; continue }
            throw ("Device-code poll failed: {0}" -f $_.Exception.Message)
        }
    }
    throw "Device-code flow timed out - no sign-in completed before expiry."
}

function Invoke-GraphRequest {
    <#
    .SYNOPSIS GET a Graph URL with pagination (@odata.nextLink) and RBAC-aware errors.
    Returns a flat array of `value` items (or the whole object if there is no `value`).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $false)][string]$Method = "Get",
        [Parameter(Mandatory = $false)][string]$Label = "Graph request"
    )

    $headers = @{ Authorization = "Bearer $AccessToken"; Accept = "application/json" }
    $results = @()
    $next = $Uri
    $attempt = 0

    while ($next) {
        try {
            $resp = Invoke-RestMethod -Uri $next -Method $Method -Headers $headers
            if ($null -ne $resp.value) { $results += $resp.value } else { $results += $resp }
            $next = $resp."@odata.nextLink"
        }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            $body = $null
            try { $body = $_.ErrorDetails.Message | ConvertFrom-Json } catch { }

            if ($status -eq 429 -and $attempt -lt 3) {
                $wait = 5
                if ($_.Exception.Response.Headers["Retry-After"]) { $wait = [int]$_.Exception.Response.Headers["Retry-After"] }
                Write-Warning "Graph throttled (429) on $Label - waiting ${wait}s and retrying."
                Start-Sleep -Seconds $wait; $attempt++; continue
            }

            if ($status -eq 401) {
                Write-Host "`n[401] $Label - token rejected. Check tenant/client id, token expiry, and that the token audience is graph.microsoft.com." -ForegroundColor Red
            }
            elseif ($status -eq 403) {
                Write-Host "`n[403] $Label - FORBIDDEN. This is the RBAC demo in action:" -ForegroundColor Red
                Write-Host "  1. Graph gate: does the token have the scope/role for this endpoint?"
                Write-Host "     (see Show-TokenClaims output above - scp for delegated, roles for app-only)"
                Write-Host "  2. Intune RBAC gate: does the user / service principal have an Intune"
                Write-Host "     role assignment covering this resource? Intune admin center >"
                Write-Host "     Tenant administration > Roles. Read Only Operator can read devices;"
                Write-Host "     a write needs a role with that write permission + scope tags."
                Write-Host "  3. Was admin consent granted? Application permissions do nothing until then."
                if ($body.error.message) { Write-Host ("  Graph said: {0}" -f $body.error.message) }
            }
            elseif ($body.error.message) {
                Write-Host ("`n[{0}] {1}: {2}" -f $status, $Label, $body.error.message) -ForegroundColor Red
            }
            else {
                Write-Host ("`n[{0}] {1}: {2}" -f $status, $Label, $_.Exception.Message) -ForegroundColor Red
            }
            return $null
        }
    }
    return $results
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host "Intune + Microsoft Graph - OAuth / RBAC demo" -ForegroundColor Green
Write-Host ("  Tenant   : {0}" -f $TenantId)
Write-Host ("  ClientId : {0}" -f $ClientId)
Write-Host ("  AuthMode : {0}" -f $AuthMode)

if ($AuthMode -eq "ClientCredentials") {
    $accessToken = Get-ClientCredentialsToken -TenantId $TenantId -ClientId $ClientId `
        -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint
}
else {
    $accessToken = Get-DeviceCodeToken -TenantId $TenantId -ClientId $ClientId -Scopes $DelegatedScopes
}

$null = Show-TokenClaims -AccessToken $accessToken
Write-Host "`nToken acquired. Calling Graph - no token value is printed or saved." -ForegroundColor Green

# 1) Managed devices - the core Intune RBAC-protected resource.
#    Needs DeviceManagementManagedDevices.Read.All + an Intune role that can read devices.
Write-Host "`n=== 1. Managed devices (GET /deviceManagement/managedDevices) ===" -ForegroundColor Cyan
$devicesUri = "{0}/deviceManagement/managedDevices?`$top={1}&`$select=id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,userPrincipalName" -f $GraphBase, $Top
$devices = Invoke-GraphRequest -AccessToken $accessToken -Uri $devicesUri -Label "List managed devices"
if ($devices) {
    $devices | Select-Object deviceName, operatingSystem, osVersion, complianceState, userPrincipalName, lastSyncDateTime |
        Format-Table -AutoSize | Out-String | Write-Host
    Write-Host ("  Returned {0} device(s) in this page." -f $devices.Count)
    if ($ExportCsv) {
        $devices | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host ("  Exported to {0}" -f $ExportCsv)
    }
}
else {
    Write-Host "  No devices returned - see the 403/401 note above. That failure IS the demo result: fix the gate it points to and re-run."
}

# 2) Compliance policies - a second read, different permission family.
Write-Host "`n=== 2. Device compliance policies (GET /deviceManagement/deviceCompliancePolicies) ===" -ForegroundColor Cyan
$policies = Invoke-GraphRequest -AccessToken $accessToken `
    -Uri ("{0}/deviceManagement/deviceCompliancePolicies?`$top={1}&`$select=id,displayName,description" -f $GraphBase, $Top) `
    -Label "List compliance policies"
if ($policies) { $policies | Select-Object displayName, description | Format-Table -AutoSize | Out-String | Write-Host }

# 3) RBAC itself - list the role definitions and assignments that gate 1) and 2).
#    Needs DeviceManagementRBAC.Read.All. If THIS call 403s, you cannot even
#    inspect RBAC through Graph - check it in the Intune admin center instead.
Write-Host "`n=== 3. Intune RBAC role definitions (GET /deviceManagement/roleDefinitions) ===" -ForegroundColor Cyan
$roleDefs = Invoke-GraphRequest -AccessToken $accessToken `
    -Uri ("{0}/deviceManagement/roleDefinitions?`$select=id,displayName,description,isBuiltIn" -f $GraphBase) `
    -Label "List Intune role definitions"
if ($roleDefs) { $roleDefs | Select-Object displayName, isBuiltIn, description | Format-Table -AutoSize | Out-String | Write-Host }

Write-Host "`n=== 4. Intune RBAC role assignments (GET /deviceManagement/roleAssignments) ===" -ForegroundColor Cyan
$roleAssignments = Invoke-GraphRequest -AccessToken $accessToken `
    -Uri ("{0}/deviceManagement/roleAssignments?`$select=id,displayName,description" -f $GraphBase) `
    -Label "List Intune role assignments"
if ($roleAssignments) {
    $roleAssignments | Select-Object displayName, description | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "  Tip: expand a single assignment to see its members / scopeMembers -"
    Write-Host "  that tells you WHO has the role and WHICH devices/users it covers."
}

# 5) Optional privileged write - deliberately gated, off by default.
if ($TryPrivilegedWrite) {
    Write-Host "`n=== 5. Privileged write test: syncDevice (POST .../managedDevices/{id}/syncDevice) ===" -ForegroundColor Yellow
    if (-not $devices -or $devices.Count -eq 0) {
        Write-Host "  Skipped - no device id available from step 1."
    }
    else {
        $target = $devices[0]
        Write-Host ("  Target: {0} ({1}) - this will ask Intune to sync it." -f $target.deviceName, $target.id)
        $syncUri = "{0}/deviceManagement/managedDevices/{1}/syncDevice" -f $GraphBase, $target.id
        $syncResult = Invoke-GraphRequest -AccessToken $accessToken -Uri $syncUri -Method "Post" -Label "Sync device (write)"
        if ($syncResult -ne $null) { Write-Host "  Sync request accepted (204/200). The write gate passed." -ForegroundColor Green }
        else { Write-Host "  Sync was refused - expected for a read-only token/role. See the 403 note above." -ForegroundColor Yellow }
    }
}
else {
    Write-Host "`n=== 5. Privileged write test: skipped ===" -ForegroundColor DarkGray
    Write-Host "  Re-run with -TryPrivilegedWrite to POST syncDevice for the first device."
    Write-Host "  It needs a write permission + an Intune role with Remote tasks / Sync device."
}

Write-Host "`nDone. What to try next:" -ForegroundColor Green
Write-Host "  - Re-run with -AuthMode DeviceCode as a user with NO Intune role: expect 403 on step 1."
Write-Host "  - Grant that user Read Only Operator, re-run: step 1 should succeed."
Write-Host "  - Re-run with -TryPrivilegedWrite as that read-only user: expect 403 on step 5."
Write-Host "  - Compare the token claims between the two auth modes: scp (delegated) vs roles (app-only)."
