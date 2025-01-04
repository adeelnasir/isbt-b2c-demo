param (
  [Parameter(Mandatory = $true)]
  [string]
  [ValidateNotNullOrEmpty()]
  $StorageAccountName,

  [Parameter(Mandatory = $true)]
  [string]
  [ValidateNotNullOrEmpty()]
  $StorageAccountKey,

  [Parameter(Mandatory = $true)]
  [string]
  [ValidateNotNullOrEmpty()]
  $ContainerName,

  [Parameter(Mandatory = $true)]
  [string]
  [ValidateNotNullOrEmpty()]
  $PageTemplateDirectory
)

function Put-PageTemplateFile {
  param (
    [Parameter(Mandatory = $true)]
    $Context,

    [Parameter(Mandatory = $true)]
    $Container,

    [Parameter(Mandatory = $true)]
    [string]
    [ValidateNotNullOrEmpty()]
    $PageTemplateDirectory,

    [Parameter(Mandatory = $true)]
    [string]
    [ValidateNotNullOrEmpty()]
    $PageTemplateFile,

    [Parameter(Mandatory = $true)]
    [string]
    [ValidateNotNullOrEmpty()]
    $ContentType
  )

  $pageTemplateItem = Get-ChildItem "$($PageTemplateDirectory)\$($PageTemplateFile)" -File

  if ($container) {
    if ($pageTemplateItem) {
      Write-Host "Uploading $($pageTemplateItem.FullName.Substring($PageTemplateDirectory.Length + 1))..."

      # Write-Host "FullName $($pageTemplateItem.FullName)"
      # Write-Host "FullName + 1 $($pageTemplateItem.FullName.Substring($PageTemplateDirectory.Length + 1))"
      # Write-Host "BaseName $($pageTemplateItem.BaseName)"
      # Write-Host "Name $($pageTemplateItem.Name)"

      # $blobName = ($pageTemplateItem.FullName.Substring($PageTemplateDirectory.Length + 1)).Replace("\", "/")
      $blobName = ($pageTemplateItem.Name)
      Set-AzStorageBlobContent -File $pageTemplateItem.FullName -Container $container.Name -Blob $blobName -Properties @{"ContentType" = $ContentType} -Force -Context $context

      Write-Host "Uploaded $($pageTemplateItem.FullName.Substring($PageTemplateDirectory.Length + 1)) to $($container.CloudBlobContainer.Uri.AbsoluteUri + "/" + $blobName)..."
    }
  }
}

$context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
$container = Get-AzStorageContainer -Name $ContainerName -Context $context
# $pageTemplateFolders = @("pages")

# for ($index = 0; $index -lt $pageTemplateFolders.length; $index++)
#{
  # $pageTemplateFolder = $pageTemplateFolders[$index]  
  Put-PageTemplateFile -Context $context -Container $container -PageTemplateDirectory $PageTemplateDirectory -PageTemplateFile "\Error.html" -ContentType "text/html"
  Put-PageTemplateFile -Context $context -Container $container -PageTemplateDirectory $PageTemplateDirectory -PageTemplateFile "\Index.html" -ContentType "text/html"
# }
