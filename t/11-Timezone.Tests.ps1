# 11-Timezone.Tests.ps1
# Tests for UTC instant expiry across different host time zones in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"
. "$PSScriptRoot/DummySMTPServer.ps1"

Describe "Time Zone Invariance (UTC Expiry)" {
	Context "OTP and Refresh Token Expiry under Different Zones" {
		$testZones = @("Asia/Kolkata", "America/Los_Angeles", "Pacific/Kiritimati")

		foreach ($tz in $testZones) {
			It "verifies OTP generation and verification remain valid under TZ=$tz" {
				$prevTZ = $env:AUTH_TEST_TZ
				$env:AUTH_TEST_TZ = $tz

				$smtp = Start-DummySMTPServer
				try {
					[void](Reset-HarnessState -Storage "mock" `
						-SMTPHost $smtp.Host `
						-SMTPPort $smtp.Port `
						-SMTPUser "user@test.com" `
						-SMTPPass "pass" `
						-OTPExpiry "5m")
					[void](Invoke-Harness "/api/mock/reset")

					$email = "tztest_$($tz.Replace('/', '_'))@example.com"
					$sendRes = Invoke-Harness "/api/send-otp" @{ email = $email }
					Assert-Equal $sendRes.data.status "sent"

					$received = $smtp.WaitEmail(2000)
					Assert-NotNull $received
					Assert-NotNull $received.OTP

					$verifyRes = Invoke-Harness "/api/verify-otp" @{
						email = $email
						code  = $received.OTP
					}
					Assert-Equal $verifyRes.data.status "verified"
				} finally {
					$smtp.Stop()
					$env:AUTH_TEST_TZ = $prevTZ
				}
			}

			It "verifies refresh token lifecycle remains valid under TZ=$tz" {
				$prevTZ = $env:AUTH_TEST_TZ
				$env:AUTH_TEST_TZ = $tz

				try {
					[void](Reset-HarnessState -Storage "mock" -RefreshExpiry "1h")
					$user = "tzuser_$($tz.Replace('/', '_'))@example.com"
					[void](Invoke-Harness "/api/register-user" @{ username = $user; password = "Password12345!" })

					$genRes = Invoke-Harness "/api/generate-refresh-token" @{ user_id = $user }
					$token = $genRes.data.token

					$valRes = Invoke-Harness "/api/validate-refresh-token" @{ token = $token }
					Assert-Equal $valRes.data.user_id $user
				} finally {
					$env:AUTH_TEST_TZ = $prevTZ
				}
			}
		}
	}
}
