[CmdletBinding()]
param(
    [string]$Root = (Split-Path $PSScriptRoot -Parent),
    [Parameter(Mandatory = $true)][string]$ReportPath,
    [string]$NodePath
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath $Root).Path
$reportFile = [System.IO.Path]::GetFullPath($ReportPath)
$originalPath = $env:PATH
$probe = @'
const ts = require('typescript');
const tree = ts.createSourceFile('probe.tsx', 'const value: number = 1; const view = <div>{value}</div>;', ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
console.log(JSON.stringify({version: ts.version, errors: tree.parseDiagnostics.length}));
'@
Push-Location -LiteralPath $repoRoot
try {
    $candidates = if ($NodePath) { @((Resolve-Path -LiteralPath $NodePath).Path) } else {
        @(Get-Command node -All -CommandType Application | Select-Object -ExpandProperty Source -Unique)
    }
    $selected = $null
    foreach ($candidate in $candidates) {
        $probeOutput = & $candidate -e $probe 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $probeOutput) { continue }
        try { $parsed = ($probeOutput -join "`n") | ConvertFrom-Json } catch { continue }
        if ($parsed.errors -eq 0 -and $parsed.version) { $selected = $candidate; break }
    }
    if (-not $selected) {
        throw 'No Node runtime passed the multiline TypeScript/TSX compiler probe. Provision TypeScript and a native Node runtime; no audit grade was produced.'
    }
    $env:PATH = (Split-Path $selected -Parent) + [System.IO.Path]::PathSeparator + $originalPath
    $output = & forge qa --repo-wide --root $repoRoot
    $auditExit = $LASTEXITCODE
    if ($auditExit -ne 0) { throw "ForgeLine command failed with exit $auditExit" }
    $raw = $output -join "`n"
    $audit = $raw | ConvertFrom-Json
    if ($audit.metrics.scope.kind -ne 'repo_wide') { throw 'ForgeLine did not return the requested repository scope.' }
    [System.IO.File]::WriteAllText($reportFile, $raw, [System.Text.UTF8Encoding]::new($false))
    [ordered]@{
        grade = $audit.grade
        passed = $audit.passed
        report = $reportFile
        node = $selected
        typescript = $parsed.version
        scope = $audit.metrics.scope.kind
        limits = 'ForgeLine static inventory and name-based test-intent metrics; not runtime coverage or security certification.'
    } | ConvertTo-Json
    if (-not $audit.passed) { exit 1 }
} finally {
    $env:PATH = $originalPath
    Pop-Location
}
