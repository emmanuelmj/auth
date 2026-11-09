# 04-JWT.Tests.ps1
# Tests for JWT creation, validation, and claim verification in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"

Describe "JWT Generation and Validation" {
	Context "GenerateToken Edge Cases" {
		It "rejects empty usernames" {
			[void](Reset-HarnessState -Storage "mock")
			Assert-Throws {
				[void](Invoke-Harness "/api/generate-token" @{ username = "" })
			} "required field cannot be empty"
		}

		It "rejects generation when JWT secret is not configured" {
			[void](Invoke-Harness "/api/init" @{ jwt_secret = $null })
			Assert-Throws {
				[void](Invoke-Harness "/api/generate-token" @{ username = "alice@test.com" })
			} "auth package not initialized"
		}

		It "generates a valid JWT token with default configured expiry" {
			[void](Reset-HarnessState -Storage "mock" -JWTExpiry "1h")
			$res = Invoke-Harness "/api/generate-token" @{ username = "alice@test.com" }
			Assert-NotNull $res.data.token
			Assert-True ($res.data.token.Split('.').Length -eq 3) "JWT must consist of three period-separated parts"
		}

		It "generates a token with custom expiry override" {
			$res = Invoke-Harness "/api/generate-token" @{
				username = "alice@test.com"
				expiry   = "10m"
			}
			Assert-NotNull $res.data.token
			Assert-True ($res.data.token.Length -gt 20)
		}
	}

	Context "ValidateToken and LoginJWT" {
		It "validates a fresh token and extracts claims" {
			[void](Reset-HarnessState -Storage "mock" -JWTExpiry "1h")
			$tokenRes = Invoke-Harness "/api/generate-token" @{ username = "alice@test.com" }
			$token = $tokenRes.data.token

			$valRes = Invoke-Harness "/api/validate-token" @{ token = $token }
			Assert-Equal $valRes.data.user_id "alice@test.com"

			$loginRes = Invoke-Harness "/api/login-jwt" @{ token = $token }
			Assert-Equal $loginRes.data.user_id "alice@test.com"
		}

		It "rejects expired tokens" {
			# Generate token with negative duration so it is expired immediately
			$tokenRes = Invoke-Harness "/api/generate-token" @{
				username = "alice@test.com"
				expiry   = "-1s"
			}
			$token = $tokenRes.data.token

			Assert-Throws {
				[void](Invoke-Harness "/api/validate-token" @{ token = $token })
			} "token is expired"
		}

		It "rejects tampered or corrupt tokens" {
			$tokenRes = Invoke-Harness "/api/generate-token" @{ username = "alice@test.com" }
			$parts = $tokenRes.data.token.Split('.')
			$tampered = "$($parts[0]).$($parts[1]).invalidsignature123"

			Assert-Throws {
				[void](Invoke-Harness "/api/validate-token" @{ token = $tampered })
			} "signature is invalid"

			Assert-Throws {
				[void](Invoke-Harness "/api/validate-token" @{ token = "completely-malformed-token" })
			} "token contains an invalid number of segments"
		}

		It "rejects tokens signed with a different secret" {
			[void](Reset-HarnessState -Storage "mock" -JWTSecret "secret-number-one-32-bytes-long!")
			$tokenRes = Invoke-Harness "/api/generate-token" @{ username = "alice@test.com" }
			$token = $tokenRes.data.token

			# Reinitialize with different secret
			[void](Reset-HarnessState -Storage "mock" -JWTSecret "different-secret-32-bytes-long!")
			Assert-Throws {
				[void](Invoke-Harness "/api/validate-token" @{ token = $token })
			} "signature is invalid"
		}
	}
}
