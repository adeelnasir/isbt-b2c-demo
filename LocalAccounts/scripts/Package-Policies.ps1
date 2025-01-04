param (
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = "",
  [Parameter(Mandatory = $false)] [string] $IdentityExperienceFrameworkApplicationDisplayName = "IdentityExperienceFramework",
  [Parameter(Mandatory = $false)] [string] $ProxyIdentityExperienceFrameworkApplicationDisplayName = "ProxyIdentityExperienceFramework",
  [Parameter(Mandatory = $false)] [string] $AttributeApplicationDisplayName = "b2c-extensions-app. Do not modify. Used by AADB2C for storing user data.",
  [Parameter(Mandatory = $false)] [string] $InputPolicyDirectoryPath = "",
  [Parameter(Mandatory = $false)] [string] $OutputPolicyDirectoryPath = "",
  [Parameter(Mandatory = $false)] [hashtable] $CustomPolicyVariables = @{}
)
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