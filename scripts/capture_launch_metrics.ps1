param(
  [string]$Package = "factoryline-code-factory",
  [string]$Repo = "zrk222/code-factory",
  [string]$Campaign = "",
  [string]$PostUrl = "",
  [string]$OutDir = ".factory/launch-metrics"
)

$ErrorActionPreference = "Stop"
$observedAt = [DateTime]::UtcNow.ToString("o")
$destination = Join-Path $OutDir ((Get-Date -Format "yyyy-MM-ddTHHmmssZ") + ".json")
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$errors = @()
$sources = [ordered]@{}

function Get-SourceJson([string]$Name, [scriptblock]$Command) {
  try {
    $sources[$Name] = & $Command
  } catch {
    $errors += [ordered]@{ source = $Name; message = $_.Exception.Message }
  }
}

$base = "https://pypistats.org/api/packages/$Package"
Get-SourceJson "pypi_recent" { Invoke-RestMethod "$base/recent" }
Get-SourceJson "pypi_overall_without_mirrors" { Invoke-RestMethod "$base/overall?mirrors=false" }
Get-SourceJson "pypi_system" { Invoke-RestMethod "$base/system" }

if (Get-Command gh -ErrorAction SilentlyContinue) {
  Get-SourceJson "github_views" { gh api "repos/$Repo/traffic/views" | ConvertFrom-Json }
  Get-SourceJson "github_clones" { gh api "repos/$Repo/traffic/clones" | ConvertFrom-Json }
}

$receipt = [ordered]@{
  schema = "factory.launch-metrics.v1"
  observed_at = $observedAt
  package = $Package
  repository = $Repo
  campaign = [ordered]@{ name = $Campaign; post_url = $PostUrl }
  sources = $sources
  errors = $errors
  interpretation = "Raw source data only. Download events, views, and clones are not unique users or attributed conversions."
}

$receipt | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $destination -Encoding utf8
Write-Output $destination
if ($errors.Count -gt 0) { exit 1 }
