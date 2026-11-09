# HarnessClient.ps1
# Client helper for communicating with the Go auth test harness server.
# Uses tab indentation.

$global:HarnessUrl = ""
$global:HarnessProcess = $null

function Get-HarnessBinary {
	$scriptDir = $PSScriptRoot
	$binDir = Join-Path (Split-Path $scriptDir -Parent) "bin"
	$exeName = if ($IsWindows) { "auth-harness.exe" } else { "auth-harness" }
	$harnessBin = Join-Path $binDir $exeName
	if (-not (Test-Path $harnessBin)) {
		if (-not (Test-Path $binDir)) {
			[void](New-Item -ItemType Directory -Path $binDir -Force)
		}
		$harnessSrc = Join-Path $scriptDir "harness"
		& go build -o $harnessBin "$harnessSrc/main.go" "$harnessSrc/mock_storage.go"
	}
	return $harnessBin
}

function Start-HarnessServer {
	[CmdletBinding()]
	param()

	if ($null -ne $global:HarnessProcess -and -not $global:HarnessProcess.HasExited) {
		return $global:HarnessUrl
	}

	$bin = Get-HarnessBinary
	$psi = [System.Diagnostics.ProcessStartInfo]::new()
	$psi.FileName = $bin
	$psi.Arguments = "server -port 0"
	$psi.RedirectStandardOutput = $true
	$psi.RedirectStandardError = $true
	$psi.UseShellExecute = $false
	$psi.CreateNoWindow = $true

	$proc = [System.Diagnostics.Process]::Start($psi)
	$global:HarnessProcess = $proc

	# Read READY line with timeout
	$sw = [System.Diagnostics.Stopwatch]::StartNew()
	$url = ""
	while ($sw.ElapsedMilliseconds -lt 5000) {
		if ($proc.HasExited) {
			$err = $proc.StandardError.ReadToEnd()
			throw "Harness process terminated prematurely: $err"
		}
		$line = $proc.StandardOutput.ReadLine()
		if ($null -ne $line -and $line.StartsWith("READY: ")) {
			$url = $line.Substring(7).Trim()
			break
		}
		[System.Threading.Thread]::Sleep(10)
	}

	if ([string]::IsNullOrWhiteSpace($url)) {
		try { $proc.Kill() } catch {}
		throw "Timed out waiting for harness server READY signal"
	}

	$global:HarnessUrl = $url
	return $url
}

function Stop-HarnessServer {
	[CmdletBinding()]
	param()

	if ($null -ne $global:HarnessProcess) {
		try {
			if (-not $global:HarnessProcess.HasExited) {
				$global:HarnessProcess.Kill()
				$global:HarnessProcess.WaitForExit(1000)
			}
			$global:HarnessProcess.Dispose()
		} catch {}
		$global:HarnessProcess = $null
		$global:HarnessUrl = ""
	}
}

function Invoke-Harness {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$Endpoint,
		[Parameter(Position = 1)]
		$Body = $null,
		[string]$Method = "POST"
	)

	if ([string]::IsNullOrWhiteSpace($global:HarnessUrl)) {
		[void](Start-HarnessServer)
	}

	$uri = "$global:HarnessUrl$Endpoint"
	$headers = @{ "Content-Type" = "application/json" }
	$jsonBody = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 10 -Compress } else { "{}" }

	try {
		$resp = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body $jsonBody
		return $resp
	} catch {
		# Extract error message from response body if possible
		$msg = $_.Exception.Message
		if ($_.Exception.Response) {
			try {
				$stream = $_.Exception.Response.GetResponseStream()
				$reader = [System.IO.StreamReader]::new($stream)
				$raw = $reader.ReadToEnd()
				$parsed = $raw | ConvertFrom-Json
				if ($parsed.error) {
					$msg = $parsed.error
				}
			} catch {}
		} elseif ($_.ErrorDetails -and $_.ErrorDetails.Message) {
			try {
				$parsed = $_.ErrorDetails.Message | ConvertFrom-Json
				if ($parsed.error) {
					$msg = $parsed.error
				}
			} catch {}
		}
		throw $msg
	}
}

function Reset-HarnessState {
	[CmdletBinding()]
	param(
		[string]$Storage = "mock",
		[string]$Pepper = "test-pepper-minimum-32-bytes-long-key!",
		[string]$JWTSecret = "jwt-secret-signing-key-32-bytes-long!",
		[string]$JWTExpiry = "1h",
		[string]$OTPPepper = "otp-dedicated-pepper-32-bytes-long!",
		[int]$OTPLength = 6,
		[string]$OTPExpiry = "5m",
		[string]$RefreshExpiry = "24h",
		[int]$RefreshLength = 32,
		[string]$SMTPHost = "",
		[string]$SMTPPort = "",
		[string]$SMTPUser = "",
		[string]$SMTPPass = "",
		[string]$OAuthClientID = "",
		[string]$OAuthSecret = "",
		[string]$OAuthRedirect = "",
		$Policy = $null
	)

	$payload = @{
		storage          = $Storage
		pepper           = $Pepper
		jwt_secret       = $JWTSecret
		jwt_expiry       = $JWTExpiry
		otp_pepper       = $OTPPepper
		otp_length       = $OTPLength
		otp_expiry       = $OTPExpiry
		refresh_expiry   = $RefreshExpiry
		refresh_length   = $RefreshLength
		smtp_host        = $SMTPHost
		smtp_port        = $SMTPPort
		smtp_user        = $SMTPUser
		smtp_pass        = $SMTPPass
		oauth_client_id  = $OAuthClientID
		oauth_client_secret = $OAuthSecret
		oauth_redirect   = $OAuthRedirect
		password_policy  = $Policy
	}

	return (Invoke-Harness "/api/init" $payload)
}
