# 07-RateLimit.Tests.ps1
# Tests for In-Memory Sliding-Window Rate Limiter in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"

Describe "Sliding-Window Rate Limiter" {
	Context "Configuration Validation" {
		It "rejects zero or negative MaxRequests" {
			Assert-Throws {
				[void](Invoke-Harness "/api/ratelimit/create" @{ max_requests = 0; window = "1m" })
			} "invalid input provided"

			Assert-Throws {
				[void](Invoke-Harness "/api/ratelimit/create" @{ max_requests = -5; window = "1m" })
			} "invalid input provided"
		}

		It "rejects zero or negative window duration" {
			Assert-Throws {
				[void](Invoke-Harness "/api/ratelimit/create" @{ max_requests = 10; window = "0s" })
			} "invalid input provided"

			Assert-Throws {
				[void](Invoke-Harness "/api/ratelimit/create" @{ max_requests = 10; window = "-5s" })
			} "invalid input provided"
		}
	}

	Context "Rate Limiting and Sliding Window" {
		It "allows requests within limit and denies requests exceeding limit" {
			# 3 requests allowed per 500ms window
			$createRes = Invoke-Harness "/api/ratelimit/create" @{ max_requests = 3; window = "500ms" }
			Assert-Equal $createRes.data.status "created"

			$key = "client-ip-1.2.3.4"

			# 3 allowed
			for ($i = 0; $i -lt 3; $i++) {
				$allow = Invoke-Harness "/api/ratelimit/allow" @{ key = $key }
				Assert-Equal $allow.data.status "allowed"
			}

			# 4th should be rejected
			Assert-Throws {
				[void](Invoke-Harness "/api/ratelimit/allow" @{ key = $key })
			} "rate limit exceeded"
		}

		It "tracks remaining requests accurately" {
			$key = "client-ip-1.2.3.4"
			$rem = Invoke-Harness "/api/ratelimit/remaining" @{ key = $key }
			Assert-Equal $rem.data.remaining 0 "Remaining should be 0 when limit reached"
		}

		It "resets rate limit for a key manually" {
			$key = "client-ip-1.2.3.4"
			$reset = Invoke-Harness "/api/ratelimit/reset" @{ key = $key }
			Assert-Equal $reset.data.status "reset"

			# Should now be allowed immediately
			$allow = Invoke-Harness "/api/ratelimit/allow" @{ key = $key }
			Assert-Equal $allow.data.status "allowed"
		}

		It "slides window allowing requests after window duration elapses" {
			# 2 requests per 100ms
			[void](Invoke-Harness "/api/ratelimit/create" @{ max_requests = 2; window = "100ms" })
			$key = "slidewindow-user"

			[void](Invoke-Harness "/api/ratelimit/allow" @{ key = $key })
			[void](Invoke-Harness "/api/ratelimit/allow" @{ key = $key })

			# Limit reached
			Assert-Throws {
				[void](Invoke-Harness "/api/ratelimit/allow" @{ key = $key })
			} "rate limit exceeded"

			# Wait 150ms for window to slide
			[System.Threading.Thread]::Sleep(150)

			# Should now be allowed again
			$allow = Invoke-Harness "/api/ratelimit/allow" @{ key = $key }
			Assert-Equal $allow.data.status "allowed"
		}

		It "stops the rate limiter cleanly" {
			$stopRes = Invoke-Harness "/api/ratelimit/stop"
			Assert-Equal $stopRes.data.status "stopped"
		}
	}
}
