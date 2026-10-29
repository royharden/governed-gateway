param([string]$Python = "$PSScriptRoot\..\.venv\Scripts\python.exe", [string]$Junit = '')
$ErrorActionPreference = 'Stop'
$checkArgs = @("$PSScriptRoot\check.py")
if ($Junit) { $checkArgs += @('--junit', $Junit) }
& $Python @checkArgs
exit $LASTEXITCODE
