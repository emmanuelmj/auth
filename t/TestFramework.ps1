# TestFramework.ps1
# Lightweight, zero-dependency testing DSL for PowerShell 7.
# Uses tab indentation.

if ($null -eq $global:TestStats) {
	$global:TestStats = [PSCustomObject]@{
		Total    = 0
		Passed   = 0
		Failed   = 0
		Skipped  = 0
		Failures = [System.Collections.Generic.List[PSCustomObject]]::new()
		Describe = ""
		Context  = ""
	}
}

function Reset-TestState {
	$global:TestStats.Total = 0
	$global:TestStats.Passed = 0
	$global:TestStats.Failed = 0
	$global:TestStats.Skipped = 0
	$global:TestStats.Failures.Clear()
	$global:TestStats.Describe = ""
	$global:TestStats.Context = ""
}

function Describe {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$Name,
		[Parameter(Mandatory = $true, Position = 1)]
		[scriptblock]$Script
	)

	$prev = $global:TestStats.Describe
	$global:TestStats.Describe = $Name
	Write-Host "`n=== $Name ===" -ForegroundColor Cyan
	try {
		& $Script
	} finally {
		$global:TestStats.Describe = $prev
	}
}

function Context {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$Name,
		[Parameter(Mandatory = $true, Position = 1)]
		[scriptblock]$Script
	)

	$prev = $global:TestStats.Context
	$global:TestStats.Context = $Name
	Write-Host "  --- $Name ---" -ForegroundColor DarkCyan
	try {
		& $Script
	} finally {
		$global:TestStats.Context = $prev
	}
}

function It {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$Name,
		[Parameter(Mandatory = $true, Position = 1)]
		[scriptblock]$Script
	)

	$global:TestStats.Total++
	$fullName = if ($global:TestStats.Context) {
		"$($global:TestStats.Describe) [$($global:TestStats.Context)] $Name"
	} else {
		"$($global:TestStats.Describe) $Name"
	}

	try {
		& $Script
		$global:TestStats.Passed++
		Write-Host "    [PASS] $Name" -ForegroundColor Green
	} catch {
		$global:TestStats.Failed++
		$err = $_
		$global:TestStats.Failures.Add([PSCustomObject]@{
			Test      = $fullName
			Error     = $err.ToString()
			ScriptPos = $err.InvocationInfo.PositionMessage
		})
		Write-Host "    [FAIL] $Name" -ForegroundColor Red
		Write-Host "           $($err.Exception.Message)" -ForegroundColor DarkRed
	}
}

function Skip {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$Name,
		[Parameter(Position = 1)]
		[string]$Reason = ""
	)

	$global:TestStats.Total++
	$global:TestStats.Skipped++
	$reasonText = if ($Reason) { " ($Reason)" } else { "" }
	Write-Host "    [SKIP] $Name$reasonText" -ForegroundColor Yellow
}

function Assert-Equal {
	[CmdletBinding()]
	param(
		[Parameter(Position = 0)]
		$Actual,
		[Parameter(Position = 1)]
		$Expected,
		[Parameter(Position = 2)]
		[string]$Message = ""
	)

	$match = $false
	if ($null -eq $Actual -and $null -eq $Expected) {
		$match = $true
	} elseif ($null -ne $Actual -and $null -ne $Expected) {
		if ($Actual.GetType().IsArray -and $Expected.GetType().IsArray) {
			if ($Actual.Length -eq $Expected.Length) {
				$match = $true
				for ($i = 0; $i -lt $Actual.Length; $i++) {
					if ("$($Actual[$i])" -ne "$($Expected[$i])") {
						$match = $false
						break
					}
				}
			}
		} else {
			$match = ("$Actual" -eq "$Expected")
		}
	}

	if (-not $match) {
		$prefix = if ($Message) { "$Message - " } else { "" }
		throw "${prefix}Expected: '$Expected', but got: '$Actual'"
	}
}

function Assert-True {
	[CmdletBinding()]
	param(
		[Parameter(Position = 0)]
		[bool]$Condition,
		[Parameter(Position = 1)]
		[string]$Message = "Expected condition to be true"
	)
	if (-not $Condition) {
		throw $Message
	}
}

function Assert-False {
	[CmdletBinding()]
	param(
		[Parameter(Position = 0)]
		[bool]$Condition,
		[Parameter(Position = 1)]
		[string]$Message = "Expected condition to be false"
	)
	if ($Condition) {
		throw $Message
	}
}

function Assert-Null {
	[CmdletBinding()]
	param(
		[Parameter(Position = 0)]
		$Value,
		[Parameter(Position = 1)]
		[string]$Message = "Expected value to be null"
	)
	if ($null -ne $Value) {
		throw "$Message (got: '$Value')"
	}
}

function Assert-NotNull {
	[CmdletBinding()]
	param(
		[Parameter(Position = 0)]
		$Value,
		[Parameter(Position = 1)]
		[string]$Message = "Expected value not to be null"
	)
	if ($null -eq $Value) {
		throw $Message
	}
}

function Assert-Like {
	[CmdletBinding()]
	param(
		[Parameter(Position = 0)]
		[string]$Actual,
		[Parameter(Position = 1)]
		[string]$Pattern,
		[Parameter(Position = 2)]
		[string]$Message = ""
	)
	if ($Actual -notmatch $Pattern) {
		$prefix = if ($Message) { "$Message - " } else { "" }
		throw "${prefix}String '$Actual' does not match pattern '$Pattern'"
	}
}

function Assert-Throws {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[scriptblock]$Script,
		[Parameter(Position = 1)]
		[string]$ExpectedErrorPattern = ""
	)

	$threw = $false
	$caughtMsg = ""
	try {
		& $Script
	} catch {
		$threw = $true
		$caughtMsg = $_.Exception.Message
	}

	if (-not $threw) {
		throw "Expected script to throw an exception, but it succeeded"
	}

	if ($ExpectedErrorPattern -and ($caughtMsg -notmatch $ExpectedErrorPattern)) {
		throw "Expected error matching '$ExpectedErrorPattern', but got '$caughtMsg'"
	}
}

function Get-TestReport {
	return [PSCustomObject]@{
		Total    = $global:TestStats.Total
		Passed   = $global:TestStats.Passed
		Failed   = $global:TestStats.Failed
		Skipped  = $global:TestStats.Skipped
		Success  = ($global:TestStats.Failed -eq 0)
		Failures = @($global:TestStats.Failures)
	}
}
