[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Config,
    [Parameter(Mandatory)][string]$RuntimeRoot,
    [switch]$Initialize
)
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$python = Join-Path $project '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Run uv sync --frozen --python 3.12.13 in this checkout first.'
}
if (-not [IO.Path]::IsPathFullyQualified($Config) -or
    -not [IO.Path]::IsPathFullyQualified($RuntimeRoot)) {
    throw 'Config and RuntimeRoot must be explicit absolute paths.'
}
# The runtime performs locality, immutable authority, and configuration checks.
# This wrapper neither creates stores nor changes the supplied authority lifetime.
$previousRoot = $env:GATEWAY_RUNTIME_ROOT
try {
    $env:GATEWAY_RUNTIME_ROOT = $RuntimeRoot
    $arguments = @('-m', 'gateway.bootstrap', '--config', $Config)
    if ($Initialize) { $arguments += '--initialize' }
    & $python @arguments
    $result = $LASTEXITCODE
} finally {
    $env:GATEWAY_RUNTIME_ROOT = $previousRoot
}
exit $result
