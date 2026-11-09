# Run-Tests.ps1
# Master test runner for the modular PowerShell 7 test suite.
# Uses tab indentation.

[CmdletBinding()]
param(
	[string]$Pattern = "*.Tests.ps1",
	[switch]$Short,
	[switch]$Help
)

$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
. "$scriptDir/TestFramework.ps1"

Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host "     Auth Library Modular PowerShell 7 Test Suite         " -ForegroundColor Magenta
Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host "Host PowerShell Version : $($PSVersionTable.PSVersion)" -ForegroundColor Gray
Write-Host "Execution Directory     : $scriptDir" -ForegroundColor Gray
Write-Host "Filter Pattern          : $Pattern" -ForegroundColor Gray
if ($Short) {
	Write-Host "Mode                    : Short (Unit / Mock Only)" -ForegroundColor Yellow
	$env:AUTH_SHORT_TESTS = "1"
} else {
	Write-Host "Mode                    : Full (Unit + Integration)" -ForegroundColor Cyan
	$env:AUTH_SHORT_TESTS = "0"
}

# Ensure Go harness binary is built once
$binDir = Join-Path (Split-Path $scriptDir -Parent) "bin"
$harnessSrc = Join-Path $scriptDir "harness"
$exeName = if ($IsWindows) { "auth-harness.exe" } else { "auth-harness" }
$harnessBin = Join-Path $binDir $exeName

if (Test-Path $harnessSrc) {
	Write-Host "`nEnsuring Go test harness binary is built..." -ForegroundColor Cyan
	if (-not (Test-Path $binDir)) {
		[void](New-Item -ItemType Directory -Path $binDir -Force)
	}
	$buildOutput = & go build -o $harnessBin "$harnessSrc/main.go" "$harnessSrc/mock_storage.go" 2>&1
	if ($LASTEXITCODE -ne 0) {
		Write-Host "Failed to build Go test harness:" -ForegroundColor Red
		Write-Host $buildOutput -ForegroundColor DarkRed
		exit 1
	}
	Write-Host "Go test harness ready: $harnessBin" -ForegroundColor Green
	$env:AUTH_HARNESS_BIN = $harnessBin
}

# Discover test files
$testFiles = Get-ChildItem -Path $scriptDir -Filter $Pattern | Sort-Object Name

if ($testFiles.Count -eq 0) {
	Write-Host "No test files found matching '$Pattern' in $scriptDir" -ForegroundColor Yellow
	exit 0
}

Write-Host "`nDiscovered $($testFiles.Count) test file(s):" -ForegroundColor Cyan
foreach ($f in $testFiles) {
	Write-Host "  - $($f.Name)" -ForegroundColor Gray
}

Reset-TestState
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($f in $testFiles) {
	try {
		& $f.FullName
	} catch {
		Write-Host "Unhandled exception executing test file $($f.Name): $_" -ForegroundColor Red
		$global:TestStats.Failed++
		$global:TestStats.Failures.Add([PSCustomObject]@{
			Test      = $f.Name
			Error     = $_.ToString()
			ScriptPos = $_.InvocationInfo.PositionMessage
		})
	}
}

$stopwatch.Stop()
$report = Get-TestReport

Write-Host "`n==========================================================" -ForegroundColor Magenta
Write-Host "                   Test Execution Summary                 " -ForegroundColor Magenta
Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host "Total Tests   : $($report.Total)" -ForegroundColor White
Write-Host "Passed Tests  : $($report.Passed)" -ForegroundColor Green
Write-Host "Failed Tests  : $($report.Failed)" -ForegroundColor $(if ($report.Failed -gt 0) { "Red" } else { "Green" })
Write-Host "Skipped Tests : $($report.Skipped)" -ForegroundColor Yellow
Write-Host "Duration      : $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 2))s" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Magenta

if ($report.Failed -gt 0) {
	Write-Host "`nFailed Tests Detail:" -ForegroundColor Red
	foreach ($fail in $report.Failures) {
		Write-Host "  FAIL: $($fail.Test)" -ForegroundColor Red
		Write-Host "        $($fail.Error)" -ForegroundColor DarkRed
		if ($fail.ScriptPos) {
			Write-Host "        $($fail.ScriptPos)" -ForegroundColor DarkGray
		}
	}
	exit 1
} else {
	Write-Host "`nALL TESTS PASSED!" -ForegroundColor Green
	exit 0
}
