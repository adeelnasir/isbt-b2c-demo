<#
 .Synopsis
  Connects to an Azure AD B2C tenant.
#>
function Connect-AzureADB2C
(
  [Parameter(Mandatory = $false)] [string] $ConfigFilePath = "",
  [Parameter(Mandatory = $false)] [string] $Tenant = ""
)
{
  if ("" -ne $ConfigFilePath)
  {
    $global:AzureADB2CConfig = (Get-Content -Path $ConfigFilePath | ConvertFrom-Json)
    $Tenant = $global:AzureADB2CConfig.TenantId
  }

  if ("" -eq $Tenant)
  {
    Write-Error "Tenant is missing."
    return
  }

  if (!(36 -eq $Tenant.Length -and $true -eq $Tenant.Contains("-")))
  {
    if (!($Tenant -imatch ".onmicrosoft.com"))
    {
      $Tenant = $Tenant + ".onmicrosoft.com"
    }

    $configurationRequestUrl = "https://login.microsoftonline.com/$Tenant/v2.0/.well-known/openid-configuration"
    $configurationResponseBody = Invoke-RestMethod -Uri $configurationRequestUrl
    $Tenant = $configurationResponseBody.authorization_endpoint.Split("/")[3]
  }

  $context = Connect-AzureAD -TenantId $Tenant
  $tenantId = $context[0].TenantId.Guid
  $tenantName = $context[0].TenantDomain
  $global:AzureADB2CTenantId = $tenantId
  $global:AzureADB2CTenantName = $tenantName

  if ("" -ne $ConfigFilePath)
  {
    $env:AzureADB2CClientId = $global:AzureADB2CConfig.ClientId
    $env:AzureADB2CClientSecret = $global:AzureADB2CConfig.ClientSecret
  }
}

<#
 .Synopsis
  Enable Azure AD B2C Identity Experience Framework.
#>
function Enable-AzureADB2CIdentityExperienceFramework
(
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = ""
)
{
  New-AzureADB2CIdentityExperienceFrameworkApplications -Tenant $Tenant -ClientId $ClientId -ClientSecret $ClientSecret
  New-AzureADB2CIdentityExperienceFrameworkKeySets -Tenant $Tenant -ClientId $ClientId -ClientSecret $ClientSecret
}

<#
 .Synopsis
  Create the Azure AD B2C Graph application.
#>
function New-AzureADB2CGraphApplication
(
  [Parameter(Mandatory = $false)] [string] $DisplayName = "b2c-graph-app",
  [Parameter(Mandatory = $false)] [switch] $CreateConfigFile = $false
)
{
  $tenantId = $global:AzureADB2CTenantId
  $tenantName = $global:AzureADB2CTenantName

  $application = Get-AzureADApplication -SearchString $DisplayName

  if ($null -ne $application)
  {
    Write-Error "Application $DisplayName already exists."
    return
  }

  $requiredResourceAccesses = @()
  $requiredAzureADGraphApplicationAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
  $requiredAzureADGraphApplicationAccess.ResourceAppId = "00000002-0000-0000-c000-000000000000" # Azure Active Directory Graph
  $requiredAzureADGraphApplicationAccess.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "78c8a3c8-a07e-4b9e-af1b-b5ccab50a175","Role" # Directory.ReadWrite.All
  $requiredResourceAccesses += $requiredAzureADGraphApplicationAccess
  $requiredMicrosoftGraphApplicationAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
  $requiredMicrosoftGraphApplicationAccess.ResourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
  $requiredMicrosoftGraphApplicationAccess.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9","Role" # Application.ReadWrite.All
  $requiredMicrosoftGraphApplicationAccess.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "19dbc75e-c2e2-444c-a770-ec69d8559fc7","Role" # Directory.ReadWrite.All
  $requiredMicrosoftGraphApplicationAccess.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "65319a09-a2be-469d-8782-f6b07debf789","Role" # IdentityUserFlow.ReadWrite.All
  $requiredMicrosoftGraphApplicationAccess.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "79a677f7-b79d-40d0-a36a-3e6f8688dd7a","Role" # Policy.ReadWrite.TrustFramework
  $requiredMicrosoftGraphApplicationAccess.ResourceAccess += New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "4a771c9a-1cf2-4609-b88e-3d3e02d539cd","Role" # TrustFrameworkKeySet.ReadWrite.All
  $requiredResourceAccesses += $requiredMicrosoftGraphApplicationAccess

  $application = New-AzureADApplication -DisplayName $DisplayName -IdentifierUris @("https://$tenantName/$DisplayName") -RequiredResourceAccess $requiredResourceAccesses

  Write-Output $application
  Write-Host "Application $DisplayName created."

  Write-Host "Creating application password credential..."

  $applicationPasswordCredential = New-AzureADApplicationPasswordCredential -ObjectId $application.ObjectId

  Write-Output $applicationPasswordCredential
  Write-Host "Application password credential created."

  Write-Host "Creating service principal..."

  $servicePrincipal = New-AzureADServicePrincipal -AppId $application.AppId -AccountEnabled $true -AppRoleAssignmentRequired $false -DisplayName $DisplayName

  Write-Output $servicePrincipal
  Write-Host "Service principal created."

  $env:AzureADB2CClientId = $application.AppId
  $env:AzureADB2CClientSecret = $applicationPasswordCredential.Value
  $global:AzureADB2CClientId = $application.AppId
  $global:AzureADB2CClientSecret = $applicationPasswordCredential.Value

  if ($CreateConfigFile)
  {
    $configFilePath = (Get-Location).Path
    $config = (Get-Content "$configFilePath\appsettings.json" | ConvertFrom-Json)
    $config.TenantId = $tenantId
    $config.TenantName = $tenantName
    $config.ClientId = $application.AppId
    $config.ClientSecret = $applicationPasswordCredential.Value
    $configFilePath = "$configFilePath\appsettings_" + $tenantName.Split(".")[0] + ".json"
    Set-Content -Path $configFilePath -Value ($config | ConvertTo-Json -Depth 10)
  }
}

<#
 .Synopsis
  Create an Azure AD B2C Identity Experience Framework application.
#>
function New-AzureADB2CIdentityExperienceFrameworkApplication
(
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = "",
  [Parameter(Mandatory = $true)] [string] $ApplicationDisplayName,
  [Parameter(Mandatory = $false)] [boolean] $ApplicationIsFallbackPublicClient = $false,
  [Parameter(Mandatory = $false)] [object] $ApplicationRequiredResourceAccess
)
{
  if ("" -eq $Tenant)
  {
    $Tenant = $global:AzureADB2CTenantId
  }
  else
  {
    if (!(36 -eq $Tenant.Length -and $true -eq $Tenant.Contains("-")))
    {
      if (!($Tenant -imatch ".onmicrosoft.com"))
      {
        $Tenant = $Tenant + ".onmicrosoft.com"
      }

      $configurationRequestUrl = "https://login.microsoftonline.com/$Tenant/v2.0/.well-known/openid-configuration"
      $configurationResponseBody = Invoke-RestMethod -Uri $configurationRequestUrl
      $Tenant = $configurationResponseBody.authorization_endpoint.Split("/")[3]
    }
  }

  if ("" -eq $ClientId)
  {
    $ClientId = $env:AzureADB2CClientId
  }

  if ("" -eq $ClientSecret)
  {
    $ClientSecret = $env:AzureADB2CClientSecret
  }

  $tokenRequestUrl = "https://login.microsoftonline.com/$Tenant/oauth2/token"

  $tokenRequestBody = @{
    grant_type = "client_credentials"
    client_id = $ClientId
    client_secret = $ClientSecret
    resource = "https://graph.microsoft.com/"
    scope = "https://graph.microsoft.com/.default"
  }

  $tokenResponseBody = Invoke-RestMethod -Method Post -Uri $tokenRequestUrl -Body $tokenRequestBody

  $listDomainsRequestUrl = "https://graph.microsoft.com/beta/domains"
  $listDomainsResponseBody = Invoke-RestMethod -Method Get -Uri $listDomainsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listDomainsResponseBody.value.Length)
  {
    Write-Warning "Domains don't exist."
    return
  }

  $defaultDomain = $listDomainsResponseBody.value | Where { $_.isDefault -eq $true }
  
  $listApplicationsRequestUrl = "https://graph.microsoft.com/beta/applications?`$filter=displayName eq '$ApplicationDisplayName'"
  $listApplicationsResponseBody = Invoke-RestMethod -Method Get -Uri $listApplicationsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -ne $listApplicationsResponseBody.value.Length)
  {
    Write-Warning "Application $ApplicationDisplayName already exists."

    Write-Output $listApplicationsResponseBody.value[0]
    return
  }

  Write-Host "Creating application $ApplicationDisplayName..."

  $createApplicationRequestUrl = "https://graph.microsoft.com/beta/applications"

  $createApplicationRequestBody = @{
    displayName = $ApplicationDisplayName
    identifierUris = @(
      "https://$($defaultDomain.id)/$ApplicationDisplayName"
    )
    isFallbackPublicClient = $ApplicationIsFallbackPublicClient
    api = @{
      oauth2PermissionScopes = @(
        @{
          id = [guid]::NewGuid()
          adminConsentDescription = "Allow the application to access $ApplicationDisplayName on behalf of the signed-in user."
          adminConsentDisplayName = "Access $ApplicationDisplayName"
          isEnabled = $true
          type = "Admin"
          value = "user_impersonation"
        }
      )
    }
    requiredResourceAccess = @()
    signInAudience = "AzureADMyOrg"
  }

  if ($null -ne $ApplicationRequiredResourceAccess)
  {
    $createApplicationRequestBody.requiredResourceAccess += $ApplicationRequiredResourceAccess
  }

  $createApplicationResponseBody = Invoke-RestMethod -Method Post -Uri $createApplicationRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ContentType "application/json" -Body $($createApplicationRequestBody | ConvertTo-Json -Depth 10)

  Write-Host "Application $ApplicationDisplayName created."

  Write-Output $createApplicationResponseBody

  Write-Host "Creating service principal..."

  $createServicePrincipalRequestUrl = "https://graph.microsoft.com/beta/servicePrincipals"

  $createServicePrincipalRequestBody = @{
    appId = $createApplicationResponseBody.appId
  }

  $createServicePrincipalResponseBody = Invoke-RestMethod -Method Post -Uri $createServicePrincipalRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ContentType "application/json" -Body $($createServicePrincipalRequestBody | ConvertTo-Json -Depth 10)

  Write-Host "Service principal created."

  Set-AzureADB2COauth2PermissionGrants -Tenant $Tenant -ClientId $ClientId -ClientSecret $ClientSecret -ApplicationAppId $createApplicationResponseBody.appId
}

<#
 .Synopsis
  Create Azure AD B2C Identity Experience Framework applications.
#>
function New-AzureADB2CIdentityExperienceFrameworkApplications
(
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = "",
  [Parameter(Mandatory = $false)] [string] $ApplicationDisplayName = "IdentityExperienceFramework"
)
{
  $identityExperienceFrameworkApplicationDisplayName = $ApplicationDisplayName

  $identityExperienceFrameworkApplicationRequiredResourceAccess = @(
    @{
      resourceAppId = "00000003-0000-0000-c000-000000000000"
      resourceAccess = @(
        @{
          id = "37f7f235-527c-4136-accd-4a02d197296e"
          type = "Scope"
        },
        @{
          id = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
          type = "Scope"
        }
      )
    }
  )

  $identityExperienceFrameworkApplication = New-AzureADB2CIdentityExperienceFrameworkApplication -Tenant $Tenant -ClientId $ClientId -ClientSecret $ClientSecret -ApplicationDisplayName $identityExperienceFrameworkApplicationDisplayName -ApplicationIsFallbackPublicClient $false -ApplicationRequiredResourceAccess $identityExperienceFrameworkApplicationRequiredResourceAccess

  $proxyIdentityExperienceFrameworkApplicationDisplayName = "Proxy$ApplicationDisplayName"

  $proxyIdentityExperienceFrameworkApplicationRequiredResourceAccess = @(
    @{
      resourceAppId = "00000003-0000-0000-c000-000000000000"
      resourceAccess = @(
        @{
          id = "37f7f235-527c-4136-accd-4a02d197296e"
          type = "Scope"
        },
        @{
          id = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
          type = "Scope"
        }
      )
    },
    @{
      resourceAppId = $identityExperienceFrameworkApplication.appId
      resourceAccess = @(
        @{
          id = $identityExperienceFrameworkApplication.api.oauth2PermissionScopes[0].id
          type = "Scope"
        }
      )
    }
  )

  $proxyIdentityExperienceFrameworkApplication = New-AzureADB2CIdentityExperienceFrameworkApplication -Tenant $Tenant -ClientId $ClientId -ClientSecret $ClientSecret -ApplicationDisplayName $proxyIdentityExperienceFrameworkApplicationDisplayName -ApplicationIsFallbackPublicClient $true -ApplicationRequiredResourceAccess $proxyIdentityExperienceFrameworkApplicationRequiredResourceAccess
}

<#
 .Synopsis
  Create an Azure AD B2C Identity Experience Framework attribute.
#>
function New-AzureADB2CIdentityExperienceFrameworkAttribute
(
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = "",
  [Parameter(Mandatory = $false)] [string] $ApplicationDisplayName = "b2c-extensions-app. Do not modify. Used by AADB2C for storing user data.",
  [Parameter(Mandatory = $true)] [string] $AttributeDisplayName,
  [Parameter(Mandatory = $false)] [string] $AttributeDescription = "",
  [Parameter(Mandatory = $false)] [string] $AttributeDataType = "string"
)
{
  if ("" -eq $Tenant)
  {
    $Tenant = $global:AzureADB2CTenantId
  }
  else
  {
    if (!(36 -eq $Tenant.Length -and $true -eq $Tenant.Contains("-")))
    {
      if (!($Tenant -imatch ".onmicrosoft.com"))
      {
        $Tenant = $Tenant + ".onmicrosoft.com"
      }

      $configurationRequestUrl = "https://login.microsoftonline.com/$Tenant/v2.0/.well-known/openid-configuration"
      $configurationResponseBody = Invoke-RestMethod -Uri $configurationRequestUrl
      $Tenant = $configurationResponseBody.authorization_endpoint.Split("/")[3]
    }
  }

  if ("" -eq $ClientId)
  {
    $ClientId = $env:AzureADB2CClientId
  }

  if ("" -eq $ClientSecret)
  {
    $ClientSecret = $env:AzureADB2CClientSecret
  }

  $tokenRequestUrl = "https://login.microsoftonline.com/$Tenant/oauth2/token"

  $tokenRequestBody = @{
    grant_type = "client_credentials"
    client_id = $ClientId
    client_secret = $ClientSecret
    resource = "https://graph.microsoft.com/"
    scope = "https://graph.microsoft.com/.default"
  }

  $tokenResponseBody = Invoke-RestMethod -Method Post -Uri $tokenRequestUrl -Body $tokenRequestBody

  $listApplicationsRequestUrl = "https://graph.microsoft.com/beta/applications?`$filter=displayName eq '$ApplicationDisplayName'"
  $listApplicationsResponseBody = Invoke-RestMethod -Method Get -Uri $listApplicationsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listApplicationsResponseBody.value.Length)
  {
    Write-Error "Application $ApplicationDisplayName doesn't exist."
    return
  }

  $listAttributesRequestUrl = "https://graph.microsoft.com/beta/identity/userFlowAttributes?`$filter=displayName eq '$AttributeDisplayName'"
  $listAttributesResponseBody = Invoke-RestMethod -Method Get -Uri $listAttributesRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -ne $listAttributesResponseBody.value.Length)
  {
    Write-Warning "Attribute $AttributeDisplayName already exists."
    return
  }

  Write-Host "Creating attribute $AttributeDisplayName..."

  $createAttributeRequestUrl = "https://graph.microsoft.com/beta/identity/userFlowAttributes"

  $createAttributeRequestBody = @{
    displayName = $AttributeDisplayName
    description = $AttributeDescription
    dataType = $AttributeDataType
  }

  $createAttributeResponseBody = Invoke-RestMethod -Method Post -Uri $createAttributeRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ContentType "application/json" -Body $($createAttributeRequestBody | ConvertTo-Json -Depth 10)

  Write-Host "Attribute $AttributeDisplayName created."

  Write-Output $createAttributeResponseBody
}

<#
 .Synopsis
  Create an Azure AD B2C Identity Experience Framework key set.
#>
function New-AzureADB2CIdentityExperienceFrameworkKeySet
(
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = "",
  [Parameter(Mandatory = $true)] [string] $KeySetName,
  [Parameter(Mandatory = $true)] [string] $KeyType,
  [Parameter(Mandatory = $true)] [string] $KeyUse,
  [Parameter(Mandatory = $false)] [string] $Secret = ""
)
{
  if ("" -eq $Tenant)
  {
    $Tenant = $global:AzureADB2CTenantId
  }
  else
  {
    if (!(36 -eq $Tenant.Length -and $true -eq $Tenant.Contains("-")))
    {
      if (!($Tenant -imatch ".onmicrosoft.com"))
      {
        $Tenant = $Tenant + ".onmicrosoft.com"
      }

      $configurationRequestUrl = "https://login.microsoftonline.com/$Tenant/v2.0/.well-known/openid-configuration"
      $configurationResponseBody = Invoke-RestMethod -Uri $configurationRequestUrl
      $Tenant = $configurationResponseBody.authorization_endpoint.Split("/")[3]
    }
  }

  if ("" -eq $ClientId)
  {
    $ClientId = $env:AzureADB2CClientId
  }

  if ("" -eq $ClientSecret)
  {
    $ClientSecret = $env:AzureADB2CClientSecret
  }

  if ($false -eq $KeySetName.StartsWith("B2C_1A_"))
  {
    $KeySetName = "B2C_1A_$KeySetName"
  }

  $KeyType = $KeyType.ToLower()

  if (!("key" -eq $KeyType -or "secret" -eq $KeyType))
  {
    Write-Error "KeyType must be 'key' or 'secret'."
    return
  }

  $KeyUse = $KeyUse.ToLower()

  if (!("sig" -eq $KeyUse -or "enc" -eq $KeyUse))
  {
    Write-Error "KeyUse must be 'sig' or 'enc'."
    return
  }

  $tokenRequestUrl = "https://login.microsoftonline.com/$Tenant/oauth2/token"

  $tokenRequestBody = @{
    grant_type = "client_credentials"
    client_id = $ClientId
    client_secret = $ClientSecret
    resource = "https://graph.microsoft.com/"
    scope = "https://graph.microsoft.com/.default"
  }

  $tokenResponseBody = Invoke-RestMethod -Method Post -Uri $tokenRequestUrl -Body $tokenRequestBody

  try
  {
    $getKeySetRequestUrl = "https://graph.microsoft.com/beta/trustFramework/keySets/$KeySetName"
    $getKeySetResponseBody = Invoke-RestMethod -Method Get -Uri $getKeySetRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue
    
    Write-Warning "Key set $($getKeySetResponseBody.id) already has $($getKeySetResponseBody.keys.Length) keys."
    return
  }
  catch
  {
  }

  Write-Host "Creating key set $KeySetName..."

  $createKeySetRequestUrl = "https://graph.microsoft.com/beta/trustFramework/keySets"

  $createKeySetRequestBody = @{
    id = $KeySetName
  }

  $createKeySetResponseBody = Invoke-RestMethod -Method Post -Uri $createKeySetRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ContentType "application/json" -Body $($createKeySetRequestBody | ConvertTo-Json -Depth 10)

  Write-Host "Key set $KeySetName created."

  Write-Output $createKeySetResponseBody

  if ("key" -eq $KeyType)
  {
    Write-Host "Generating key..."

    $generateKeyRequestUrl = "https://graph.microsoft.com/beta/trustFramework/keySets/$KeySetName/generateKey"

    $generateKeyRequestBody = @{
      use = $KeyUse
      kty = "RSA"
    }

    $generateKeyResponseBody = Invoke-RestMethod -Method Post -Uri $generateKeyRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ContentType "application/json" -Body $($generateKeyRequestBody | ConvertTo-Json -Depth 10)

    Write-Host "Key generated."
  }

  if ("secret" -eq $KeyType)
  {
    Write-Host "Uploading secret..."

    $uploadSecretRequestUrl = "https://graph.microsoft.com/beta/trustFramework/keySets/$KeySetName/uploadSecret"

    $uploadSecretRequestBody = @{
      use = $KeyUse
      k = $Secret
    }

    $uploadSecretResponseBody = Invoke-RestMethod -Method Post -Uri $uploadSecretRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ContentType "application/json" -Body $($uploadSecretRequestBody | ConvertTo-Json -Depth 10)

    Write-Host "Secret uploaded."
  }
}

<#
 .Synopsis
  Create Azure AD B2C Identity Experience Framework key sets.
#>
function New-AzureADB2CIdentityExperienceFrameworkKeySets
(
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = ""
)
{
  New-AzureADB2CIdentityExperienceFrameworkKeySet -Tenant $Tenant -ClientId $ClientId -ClientSecret $ClientSecret -KeySetName "B2C_1A_TokenSigningKeyContainer" -KeyType "key" -KeyUse "sig"
  New-AzureADB2CIdentityExperienceFrameworkKeySet -Tenant $Tenant -ClientId $ClientId -ClientSecret $ClientSecret -KeySetName "B2C_1A_TokenEncryptionKeyContainer" -KeyType "key" -KeyUse "enc"
}

<#
 .Synopsis
  Package Azure AD B2C Identity Experience Framework policies.
#>
function Package-AzureADB2CIdentityExperienceFrameworkPolicies
(
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = "",
  [Parameter(Mandatory = $false)] [string] $IdentityExperienceFrameworkApplicationDisplayName = "IdentityExperienceFramework",
  [Parameter(Mandatory = $false)] [string] $ProxyIdentityExperienceFrameworkApplicationDisplayName = "ProxyIdentityExperienceFramework",
  [Parameter(Mandatory = $false)] [string] $AttributeApplicationDisplayName = "b2c-extensions-app. Do not modify. Used by AADB2C for storing user data.",
  [Parameter(Mandatory = $false)] [string] $InputPolicyDirectoryPath = "",
  [Parameter(Mandatory = $false)] [string] $OutputPolicyDirectoryPath = "",
  [Parameter(Mandatory = $false)] [string] $VersionSettingsFilePath = "",
  [Parameter(Mandatory = $false)] [hashtable] $CustomPolicyVariables = @{}
)
{
  if ("" -eq $Tenant)
  {
    $Tenant = $global:AzureADB2CTenantId
  }
  else
  {
    if (!(36 -eq $Tenant.Length -and $true -eq $Tenant.Contains("-")))
    {
      if (!($Tenant -imatch ".onmicrosoft.com"))
      {
        $Tenant = $Tenant + ".onmicrosoft.com"
      }

      $configurationRequestUrl = "https://login.microsoftonline.com/$Tenant/v2.0/.well-known/openid-configuration"
      $configurationResponseBody = Invoke-RestMethod -Uri $configurationRequestUrl
      $Tenant = $configurationResponseBody.authorization_endpoint.Split("/")[3]
    }
  }

  if ("" -eq $ClientId)
  {
    $ClientId = $env:AzureADB2CClientId
  }

  if ("" -eq $ClientSecret)
  {
    $ClientSecret = $env:AzureADB2CClientSecret
  }

  $versionSettings = (Get-Content -Path $VersionSettingsFilePath | ConvertFrom-Json)
  $tokenRequestUrl = "https://login.microsoftonline.com/$Tenant/oauth2/token"

  $tokenRequestBody = @{
    grant_type = "client_credentials"
    client_id = $ClientId
    client_secret = $ClientSecret
    resource = "https://graph.microsoft.com/"
    scope = "https://graph.microsoft.com/.default"
  }

  $tokenResponseBody = Invoke-RestMethod -Method Post -Uri $tokenRequestUrl -Body $tokenRequestBody

  $listOrganizationsRequestUrl = "https://graph.microsoft.com/beta/organization"
  $listOrganizationsResponseBody = Invoke-RestMethod -Method Get -Uri $listOrganizationsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listOrganizationsResponseBody.value.Length)
  {
    Write-Error "Organization doesn't exist."
    return
  }

  $organization = $listOrganizationsResponseBody.value[0]

  $domain = ($organization.verifiedDomains | Where-Object { $_.isDefault -eq $true }).name

  $listApplicationsRequestUrl = "https://graph.microsoft.com/beta/applications?`$filter=displayName eq '$IdentityExperienceFrameworkApplicationDisplayName'"
  $listApplicationsResponseBody = Invoke-RestMethod -Method Get -Uri $listApplicationsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listApplicationsResponseBody.value.Length)
  {
    Write-Error "Application $IdentityExperienceFrameworkApplicationDisplayName doesn't exist."
    return
  }

  $identityExperienceFrameworkApplication = $listApplicationsResponseBody.value[0]

  $listApplicationsRequestUrl = "https://graph.microsoft.com/beta/applications?`$filter=displayName eq '$ProxyIdentityExperienceFrameworkApplicationDisplayName'"
  $listApplicationsResponseBody = Invoke-RestMethod -Method Get -Uri $listApplicationsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listApplicationsResponseBody.value.Length)
  {
    Write-Error "Application $ProxyIdentityExperienceFrameworkApplicationDisplayName doesn't exist."
    return
  }

  $proxyIdentityExperienceFrameworkApplication = $listApplicationsResponseBody.value[0]

  $listApplicationsRequestUrl = "https://graph.microsoft.com/beta/applications?`$filter=displayName eq '$AttributeApplicationDisplayName'"
  $listApplicationsResponseBody = Invoke-RestMethod -Method Get -Uri $listApplicationsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listApplicationsResponseBody.value.Length)
  {
    Write-Error "Application $AttributeApplicationDisplayName doesn't exist."
    return
  }

  $attributeApplication = $listApplicationsResponseBody.value[0]

  $builtInPolicyVariables = @{
    "{config:Tenant:Name}" = $domain
    "{config:IdentityExperienceFrameworkApplication:AppId}" = $identityExperienceFrameworkApplication.appId
    "{config:ProxyIdentityExperienceFrameworkApplication:AppId}" = $proxyIdentityExperienceFrameworkApplication.appId
    "{config:AttributeApplication:Id}" = $attributeApplication.id
    "{config:AttributeApplication:AppId}" = $attributeApplication.appId
    "{config:VersionSettings:NextVersion}" = $versionSettings.NextVersion
  }

  $policyFileNames = Get-ChildItem -Path $InputPolicyDirectoryPath -Include *.xml -Name

  if ($false -eq (Test-Path $OutputPolicyDirectoryPath))
  {
    New-Item -Path $OutputPolicyDirectoryPath -ItemType "Directory"
  }

  foreach ($policyFileName in $policyFileNames)
  {
    $inputPolicyFile = (Join-Path -Path $InputPolicyDirectoryPath -ChildPath $policyFileName)
    $policyData = Get-Content $inputPolicyFile

    foreach ($policyVariableKey in $builtInPolicyVariables.keys)
    {
      $policyData = $policyData.Replace($policyVariableKey, $builtInPolicyVariables[$policyVariableKey])
    }

    foreach ($policyVariableKey in $CustomPolicyVariables.keys)
    {
      $policyData = $policyData.Replace($policyVariableKey, $CustomPolicyVariables[$policyVariableKey])
    }

    $outputPolicyFile = (Join-Path -Path $OutputPolicyDirectoryPath -ChildPath "$($domain)-$($policyFileName)")
    Set-Content -Path $outputPolicyFile -Value $policyData
  }
}

<#
 .Synopsis
  Publish Azure AD B2C Identity Experience Framework policies.
#>
function Publish-AzureADB2CIdentityExperienceFrameworkPolicies
(
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = "",
  [Parameter(Mandatory = $false)] [string] $IdentityExperienceFrameworkApplicationDisplayName = "IdentityExperienceFramework",
  [Parameter(Mandatory = $false)] [string] $ProxyIdentityExperienceFrameworkApplicationDisplayName = "ProxyIdentityExperienceFramework",
  [Parameter(Mandatory = $false)] [string] $AttributeApplicationDisplayName = "b2c-extensions-app. Do not modify. Used by AADB2C for storing user data.",
  [Parameter(Mandatory = $false)] [string] $PolicyDirectoryPath = ""
)
{
  if ("" -eq $Tenant)
  {
    $Tenant = $global:AzureADB2CTenantId
  }
  else
  {
    if (!(36 -eq $Tenant.Length -and $true -eq $Tenant.Contains("-")))
    {
      if (!($Tenant -imatch ".onmicrosoft.com"))
      {
        $Tenant = $Tenant + ".onmicrosoft.com"
      }

      $configurationRequestUrl = "https://login.microsoftonline.com/$Tenant/v2.0/.well-known/openid-configuration"
      $configurationResponseBody = Invoke-RestMethod -Uri $configurationRequestUrl
      $Tenant = $configurationResponseBody.authorization_endpoint.Split("/")[3]
    }
  }

  if ("" -eq $ClientId)
  {
    $ClientId = $env:AzureADB2CClientId
  }

  if ("" -eq $ClientSecret)
  {
    $ClientSecret = $env:AzureADB2CClientSecret
  }

  if ("" -eq $PolicyDirectoryPath)
  {
    $PolicyDirectoryPath = (Get-Location).Path
  }

  $PolicyDirectoryPath

  $tokenRequestUrl = "https://login.microsoftonline.com/$Tenant/oauth2/token"

  $tokenRequestBody = @{
    grant_type = "client_credentials"
    client_id = $ClientId
    client_secret = $ClientSecret
    resource = "https://graph.microsoft.com/"
    scope = "https://graph.microsoft.com/.default"
  }

  $tokenResponseBody = Invoke-RestMethod -Method Post -Uri $tokenRequestUrl -Body $tokenRequestBody

  $listOrganizationsRequestUrl = "https://graph.microsoft.com/beta/organization"
  $listOrganizationsResponseBody = Invoke-RestMethod -Method Get -Uri $listOrganizationsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listOrganizationsResponseBody.value.Length)
  {
    Write-Error "Organization doesn't exist."
    return
  }

  $organization = $listOrganizationsResponseBody.value[0]

  $domain = ($organization.verifiedDomains | Where-Object { $_.isDefault -eq $true }).name

  $listApplicationsRequestUrl = "https://graph.microsoft.com/beta/applications?`$filter=displayName eq '$IdentityExperienceFrameworkApplicationDisplayName'"
  $listApplicationsResponseBody = Invoke-RestMethod -Method Get -Uri $listApplicationsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listApplicationsResponseBody.value.Length)
  {
    Write-Error "Application $IdentityExperienceFrameworkApplicationDisplayName doesn't exist."
    return
  }

  $identityExperienceFrameworkApplication = $listApplicationsResponseBody.value[0]

  $listApplicationsRequestUrl = "https://graph.microsoft.com/beta/applications?`$filter=displayName eq '$ProxyIdentityExperienceFrameworkApplicationDisplayName'"
  $listApplicationsResponseBody = Invoke-RestMethod -Method Get -Uri $listApplicationsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listApplicationsResponseBody.value.Length)
  {
    Write-Error "Application $ProxyIdentityExperienceFrameworkApplicationDisplayName doesn't exist."
    return
  }

  $proxyIdentityExperienceFrameworkApplication = $listApplicationsResponseBody.value[0]

  function BuildAzureADB2CIdentityExperienceFrameworkPolicies
  {
    $policies = @()

    $policyFileNames = Get-ChildItem -Path $PolicyDirectoryPath -Include *.xml -Name

    foreach ($policyFileName in $policyFileNames)
    {
      $policyFile = (Join-Path -Path $PolicyDirectoryPath -ChildPath $policyFileName)
      $policyData = Get-Content $policyFile
      [xml] $policyXml = $policyData

      if ($null -ne $policyXml.TrustFrameworkPolicy)
      {
        $policy = New-Object System.Object
        $policy | Add-Member -Name "PolicyId" -Type NoteProperty -Value $policyXml.TrustFrameworkPolicy.PolicyId
        $policy | Add-Member -Name "ParentPolicyId" -Type NoteProperty -Value $policyXml.TrustFrameworkPolicy.BasePolicy.PolicyId
        $policy | Add-Member -Name "HasChildPolicies" -Type NoteProperty -Value $null
        $policy | Add-Member -Name "PolicyData" -Type NoteProperty -Value $policyData
        $policy | Add-Member -Name "IsUploaded" -Type NoteProperty -Value $false
        $policies += $policy
      }
    }

    return $policies
  }

  function DeployAzureADB2CIdentityExperienceFrameworkPolicies
  (
    $Policies,
    $ParentPolicyId
  )
  {
    foreach ($policy in $policies)
    {
      if ($ParentPolicyId -eq $policy.ParentPolicyId -and $false -eq $policy.IsUploaded)
      {
        UploadAzureADB2CIdentityExperienceFrameworkPolicy -PolicyId $policy.PolicyId -PolicyData $policy.PolicyData
        $policy.IsUploaded = $true

        DeployAzureADB2CIdentityExperienceFrameworkPolicies -Policies $policies -ParentPolicyId $policy.PolicyId
      }
    }
  }

  function UploadAzureADB2CIdentityExperienceFrameworkPolicy
  (
    $PolicyId,
    $PolicyData
  )
  {
    Write-Host "Uploading policy $PolicyId..."

    try
    {
      $updatePolicyRequestUrl = "https://graph.microsoft.com/beta/trustFramework/policies/$PolicyId/`$value"
      $updatePolicyRequestBody = $PolicyData
      $updatePolicyResponseBody = Invoke-RestMethod -Method Put -Uri $updatePolicyRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ContentType "application/xml" -Body $updatePolicyRequestBody

      Write-Host "Policy $($updatePolicyResponseBody.TrustFrameworkPolicy.PublicPolicyUri) uploaded."
    }
    catch
    {
      $updatePolicyErrorResponseBodyReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
      $updatePolicyErrorResponseBodyReader.BaseStream.Position = 0
      $updatePolicyErrorResponseBodyReader.DiscardBufferedData()
      $updatePolicyErrorResponseBody = $updatePolicyErrorResponseBodyReader.ReadToEnd()
      $updatePolicyErrorResponseBodyReader.Close()

      Write-Host $updatePolicyErrorResponseBody -ForegroundColor "Red" -BackgroundColor "Black"
    }
  }

  $policies = BuildAzureADB2CIdentityExperienceFrameworkPolicies $PolicyDirectoryPath

  foreach ($policy in $policies)
  {
    $policy.HasChildPolicies = ($null -ne ($policies | Where { $_.PolicyId -eq $policy.ParentPolicyId }))
  }

  foreach ($policy in $policies)
  {
    if ($false -eq $policy.HasChildPolicies)
    {
      DeployAzureADB2CIdentityExperienceFrameworkPolicies -Policies $policies -ParentPolicyId $policy.ParentPolicyId
    }
  }
}

<#
 .Synopsis
  Set the Azure AD B2C OAuth2 permission grants.
#>
function Set-AzureADB2COauth2PermissionGrants
(
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = "",
  [Parameter(Mandatory = $true)] [string] $ApplicationAppId = ""
)
{
  if ("" -eq $Tenant)
  {
    $Tenant = $global:AzureADB2CTenantId
  }
  else
  {
    if (!(36 -eq $Tenant.Length -and $true -eq $Tenant.Contains("-")))
    {
      if (!($Tenant -imatch ".onmicrosoft.com"))
      {
        $Tenant = $Tenant + ".onmicrosoft.com"
      }

      $configurationRequestUrl = "https://login.microsoftonline.com/$Tenant/v2.0/.well-known/openid-configuration"
      $configurationResponseBody = Invoke-RestMethod -Uri $configurationRequestUrl
      $Tenant = $configurationResponseBody.authorization_endpoint.Split("/")[3]
    }
  }

  if ("" -eq $ClientId)
  {
    $ClientId = $env:AzureADB2CClientId
  }

  if ("" -eq $ClientSecret)
  {
    $ClientSecret = $env:AzureADB2CClientSecret
  }

  $tokenRequestUrl = "https://login.microsoftonline.com/$Tenant/oauth2/token"

  $tokenRequestBody = @{
    grant_type = "client_credentials"
    client_id = $ClientId
    client_secret = $ClientSecret
    resource = "https://graph.microsoft.com/"
    scope = "https://graph.microsoft.com/.default"
  }

  $tokenResponseBody = Invoke-RestMethod -Method Post -Uri $tokenRequestUrl -Body $tokenRequestBody

  $listApplicationsRequestUrl = "https://graph.microsoft.com/beta/applications?`$filter=appId eq '$ApplicationAppId'"
  $listApplicationsResponseBody = Invoke-RestMethod -Method Get -Uri $listApplicationsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listApplicationsResponseBody.value.Length)
  {
    Write-Error "Application $ApplicationAppId doesn't exist."
    return
  }

  $clientApplication = $listApplicationsResponseBody.value[0]

  $listServicePrincipalsRequestUrl = "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appId eq '$ApplicationAppId'"
  $listServicePrincipalsResponseBody = Invoke-RestMethod -Method Get -Uri $listServicePrincipalsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

  if (0 -eq $listServicePrincipalsResponseBody.value.Length)
  {
    Write-Error "Service principal $ApplicationAppId doesn't exist."
    return
  }

  $clientServicePrincipal = $listServicePrincipalsResponseBody.value[0]

  Write-Host "Granting OAuth2 permissions..."

  $startTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $expiryTime = (Get-Date).AddYears(2).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

  foreach ($requiredResourceAccess in $clientApplication.requiredResourceAccess)
  {
    $listServicePrincipalsRequestUrl = "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appId eq '$($requiredResourceAccess.resourceAppId)'"
    $listServicePrincipalsResponseBody = Invoke-RestMethod -Method Get -Uri $listServicePrincipalsRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ErrorAction SilentlyContinue

    if (0 -eq $listServicePrincipalsResponseBody.value.Length)
    {
      Write-Error "Service principal $($requiredResourceAccess.resourceAppId) doesn't exist."
      return
    }

    $resourceServicePrincipal = $listServicePrincipalsResponseBody.value[0]

    foreach ($resourceAccess in $requiredResourceAccess.resourceAccess)
    {
      $scope += ($resourceServicePrincipal.publishedPermissionScopes | Where-Object { $_.id -eq $resourceAccess.id }).value + " "
    }

    $createOauth2PermissionGrantRequestUrl = "https://graph.microsoft.com/beta/oauth2PermissionGrants"

    $createOauth2PermissionGrantRequestBody = @{
      clientId = $clientServicePrincipal.id
      consentType = "AllPrincipals"
      principalId = $null
      resourceId = $resourceServicePrincipal.id
      scope = $scope
      startTime = $startTime
      expiryTime = $expiryTime
    }

    $createOauth2PermissionGrantResponseBody = Invoke-RestMethod -Method Post -Uri $createOauth2PermissionGrantRequestUrl -Headers @{ Authorization = "$($tokenResponseBody.token_type) $($tokenResponseBody.access_token)" } -ContentType "application/json" -Body $($createOauth2PermissionGrantRequestBody | ConvertTo-Json -Depth 10)
  }

  Write-Host "OAuth2 permissions granted."
}
