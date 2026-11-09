# 09-OAuth.Tests.ps1
# Tests for OAuth login URL and callback handling in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"

Describe "Google OAuth Integration" {
	Context "Configuration and URL Generation" {
		It "rejects empty state string" {
			[void](Reset-HarnessState -Storage "mock" `
				-OAuthClientID "client-12345.apps.googleusercontent.com" `
				-OAuthSecret "client-secret-987" `
				-OAuthRedirect "http://localhost:8080/auth/callback")

			Assert-Throws {
				[void](Invoke-Harness "/api/google/login-url" @{ state = "" })
			} "required field cannot be empty"
		}

		It "rejects URL generation when OAuth is not initialized" {
			[void](Reset-HarnessState -Storage "mock")
			Assert-Throws {
				[void](Invoke-Harness "/api/google/login-url" @{ state = "random-state-123" })
			} "oauth not initialized"
		}

		It "generates a valid Google consent URL with scopes and state" {
			$clientID = "client-12345.apps.googleusercontent.com"
			$redirect = "http://localhost:8080/auth/callback"
			$state = "secure-random-state-xyz"

			[void](Reset-HarnessState -Storage "mock" `
				-OAuthClientID $clientID `
				-OAuthSecret "client-secret-987" `
				-OAuthRedirect $redirect)

			$res = Invoke-Harness "/api/google/login-url" @{ state = $state }
			Assert-NotNull $res.data.url
			$url = $res.data.url

			Assert-Like $url "^https://accounts\.google\.com/o/oauth2/auth" "URL must target Google auth endpoint"
			Assert-True ($url.Contains("client_id=$clientID")) "URL must contain client_id"
			Assert-True ($url.Contains("state=$state")) "URL must contain state parameter"
		}
	}

	Context "Callback Handling Edge Cases" {
		It "rejects empty auth code" {
			Assert-Throws {
				[void](Invoke-Harness "/api/google/callback" @{ code = "" })
			} "required field cannot be empty"
		}

		It "rejects callback when OAuth is not initialized" {
			[void](Reset-HarnessState -Storage "mock")
			Assert-Throws {
				[void](Invoke-Harness "/api/google/callback" @{ code = "valid-format-code" })
			} "oauth not initialized"
		}

		It "handles exchange error when token endpoint returns error or code is invalid" {
			[void](Reset-HarnessState -Storage "mock" `
				-OAuthClientID "client-12345" `
				-OAuthSecret "secret" `
				-OAuthRedirect "http://localhost:8080/cb")

			Assert-Throws {
				[void](Invoke-Harness "/api/google/callback" @{ code = "invalid-or-fake-code" })
			} "failed to exchange oauth code"
		}
	}
}
