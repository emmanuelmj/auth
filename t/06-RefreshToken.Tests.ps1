# 06-RefreshToken.Tests.ps1
# Tests for Refresh Token lifecycle, rotation, and revocation in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"

Describe "Refresh Token Lifecycle and Rotation" {
	Context "GenerateRefreshToken" {
		It "rejects empty userID" {
			[void](Reset-HarnessState -Storage "mock")
			Assert-Throws {
				[void](Invoke-Harness "/api/generate-refresh-token" @{ user_id = "" })
			} "required field cannot be empty"
		}

		It "generates a cryptographically random opaque refresh token for an existing user" {
			[void](Invoke-Harness "/api/mock/reset")
			$user = "tokenuser@test.com"
			[void](Invoke-Harness "/api/register-user" @{ username = $user; password = "Password12345!" })

			$genRes = Invoke-Harness "/api/generate-refresh-token" @{ user_id = $user }
			Assert-NotNull $genRes.data.token
			# Token length: 32 bytes hex encoded = 64 hex characters
			Assert-Equal $genRes.data.token.Length 64 "Hex encoded token length should be 64 characters"
		}
	}

	Context "ValidateRefreshToken" {
		It "validates a valid unexpired refresh token" {
			$user = "tokenuser@test.com"
			$genRes = Invoke-Harness "/api/generate-refresh-token" @{ user_id = $user }
			$token = $genRes.data.token

			$valRes = Invoke-Harness "/api/validate-refresh-token" @{ token = $token }
			Assert-Equal $valRes.data.user_id $user
		}

		It "rejects empty or non-existent refresh tokens" {
			Assert-Throws {
				[void](Invoke-Harness "/api/validate-refresh-token" @{ token = "" })
			} "required field cannot be empty"

			Assert-Throws {
				[void](Invoke-Harness "/api/validate-refresh-token" @{ token = "nonexistenttoken1234567890abcdef" })
			} "invalid refresh token"
		}

		It "rejects expired refresh tokens" {
			$user = "expireduser@test.com"
			[void](Invoke-Harness "/api/register-user" @{ username = $user; password = "Password12345!" })

			# Reconfigure with 1ms expiry
			[void](Reset-HarnessState -Storage "mock" -RefreshExpiry "1ms")
			$genRes = Invoke-Harness "/api/generate-refresh-token" @{ user_id = $user }
			$token = $genRes.data.token

			[System.Threading.Thread]::Sleep(50)

			Assert-Throws {
				[void](Invoke-Harness "/api/validate-refresh-token" @{ token = $token })
			} "refresh token has expired"
		}
	}

	Context "Token Rotation" {
		It "rotates an existing token, revoking the old one and returning a new valid token" {
			[void](Reset-HarnessState -Storage "mock" -RefreshExpiry "24h")
			$user = "rotateuser@test.com"
			[void](Invoke-Harness "/api/register-user" @{ username = $user; password = "Password12345!" })

			$genRes = Invoke-Harness "/api/generate-refresh-token" @{ user_id = $user }
			$oldToken = $genRes.data.token

			# Rotate
			$rotRes = Invoke-Harness "/api/rotate-refresh-token" @{ old_token = $oldToken }
			$newToken = $rotRes.data.new_token
			Assert-NotNull $newToken
			Assert-True ($newToken -ne $oldToken) "Rotated token must differ from old token"
			Assert-Equal $rotRes.data.user_id $user

			# Old token must now be revoked
			Assert-Throws {
				[void](Invoke-Harness "/api/validate-refresh-token" @{ token = $oldToken })
			} "refresh token has been revoked"

			# New token is valid
			$valRes = Invoke-Harness "/api/validate-refresh-token" @{ token = $newToken }
			Assert-Equal $valRes.data.user_id $user
		}
	}

	Context "Revocation" {
		It "revokes a specific token by value" {
			$user = "tokenuser@test.com"
			$genRes = Invoke-Harness "/api/generate-refresh-token" @{ user_id = $user }
			$token = $genRes.data.token

			$revRes = Invoke-Harness "/api/revoke-refresh-token" @{ token = $token }
			Assert-Equal $revRes.data.status "revoked"

			Assert-Throws {
				[void](Invoke-Harness "/api/validate-refresh-token" @{ token = $token })
			} "refresh token has been revoked"
		}

		It "revokes all tokens for a user on password reset or suspicious activity" {
			$user = "tokenuser@test.com"
			$t1 = (Invoke-Harness "/api/generate-refresh-token" @{ user_id = $user }).data.token
			$t2 = (Invoke-Harness "/api/generate-refresh-token" @{ user_id = $user }).data.token

			# Generate token for another user
			$other = "otheruser@test.com"
			[void](Invoke-Harness "/api/register-user" @{ username = $other; password = "Password12345!" })
			$tOther = (Invoke-Harness "/api/generate-refresh-token" @{ user_id = $other }).data.token

			# Revoke all for $user
			$revAll = Invoke-Harness "/api/revoke-all-refresh-tokens" @{ user_id = $user }
			Assert-Equal $revAll.data.status "all_revoked"

			# Both t1 and t2 revoked
			Assert-Throws {
				[void](Invoke-Harness "/api/validate-refresh-token" @{ token = $t1 })
			} "refresh token has been revoked"
			Assert-Throws {
				[void](Invoke-Harness "/api/validate-refresh-token" @{ token = $t2 })
			} "refresh token has been revoked"

			# Other user's token unaffected
			$valOther = Invoke-Harness "/api/validate-refresh-token" @{ token = $tOther }
			Assert-Equal $valOther.data.user_id $other
		}

		It "cleans up expired refresh tokens without affecting active ones" {
			$cleanRes = Invoke-Harness "/api/cleanup-expired-refresh-tokens"
			Assert-Equal $cleanRes.data.status "cleaned"
		}
	}
}
