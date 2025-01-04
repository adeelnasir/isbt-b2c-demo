param (
  [Parameter(Mandatory = $false)] [string] $Tenant = "",
  [Parameter(Mandatory = $false)] [string] $ClientId = "",
  [Parameter(Mandatory = $false)] [string] $ClientSecret = "",
  [Parameter(Mandatory = $false)] [string] $IdentityExperienceFrameworkApplicationDisplayName = "IdentityExperienceFramework",
  [Parameter(Mandatory = $false)] [string] $ProxyIdentityExperienceFrameworkApplicationDisplayName = "ProxyIdentityExperienceFramework",
  [Parameter(Mandatory = $false)] [string] $AttributeApplicationDisplayName = "b2c-extensions-app. Do not modify. Used by AADB2C for storing user data.",
  [Parameter(Mandatory = $false)] [string] $PolicyDirectoryPath = ""
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