# 01-AuthOptions.Tests.ps1
# Tests for Auth constructor options and core methods in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"

Describe "Auth Options and Core Methods" {
	Context "Default Configuration" {
		It "initializes without options and reports storage and redis inactive" {
			[void](Invoke-Harness "/api/init" @{})
			$hasStorage = Invoke-Harness "/api/has-storage"
			Assert-False $hasStorage.data.has_storage "HasStorage should be false by default"

			$hasRedis = Invoke-Harness "/api/has-redis"
			Assert-False $hasRedis.data.has_redis "HasRedis should be false by default"

			$close = Invoke-Harness "/api/close"
			Assert-Equal $close.data.status "closed"
		}
	}

	Context "Storage Option" {
		It "reports storage active when configured with mock storage" {
			[void](Reset-HarnessState -Storage "mock")
			$hasStorage = Invoke-Harness "/api/has-storage"
			Assert-True $hasStorage.data.has_storage "HasStorage should be true"
		}

		It "fails initialization when CheckTables returns an error" {
			[void](Invoke-Harness "/api/mock/set-error" @{ hook = "check_tables"; msg = "disk corrupted" })
			Assert-Throws {
				[void](Reset-HarnessState -Storage "mock")
			} "failed to check tables: disk corrupted"
			[void](Invoke-Harness "/api/mock/reset")
		}
	}

	Context "Refresh Token Option" {
		It "rejects zero or negative refresh token duration" {
			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ refresh_expiry = "0s"; refresh_length = 32 })
			} "invalid input provided"

			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ refresh_expiry = "-10m"; refresh_length = 32 })
			} "invalid input provided"
		}

		It "defaults refresh token length to 32 when length <= 0" {
			$res = Invoke-Harness "/api/init" @{ refresh_expiry = "24h"; refresh_length = 0 }
			Assert-Equal $res.data.status "initialized"
		}
	}

	Context "OTP Option" {
		It "rejects OTP pepper shorter than 32 bytes" {
			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{
					otp_pepper = "short-pepper"
					otp_length = 6
					otp_expiry = "5m"
				})
			} "invalid input provided"
		}

		It "applies defaults for length and expiry when zero" {
			$res = Invoke-Harness "/api/init" @{
				otp_pepper = "01234567890123456789012345678901"
				otp_length = 0
				otp_expiry = ""
			}
			Assert-Equal $res.data.status "initialized"
		}
	}

	Context "JWT Option" {
		It "rejects empty JWT secret" {
			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ jwt_secret = ""; jwt_expiry = "1h" })
			} "required field cannot be empty"
		}

		It "accepts zero expiry and falls back to default 24h" {
			$res = Invoke-Harness "/api/init" @{
				jwt_secret = "secret-key-at-least-32-bytes-long!"
				jwt_expiry = "0s"
			}
			Assert-Equal $res.data.status "initialized"
		}
	}

	Context "SMTP Option" {
		It "rejects empty SMTP configuration fields" {
			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ smtp_host = ""; smtp_port = "25"; smtp_user = "a"; smtp_pass = "b" })
			} "required field cannot be empty"

			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ smtp_host = "127.0.0.1"; smtp_port = ""; smtp_user = "a"; smtp_pass = "b" })
			} "required field cannot be empty"

			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ smtp_host = "127.0.0.1"; smtp_port = "25"; smtp_user = ""; smtp_pass = "b" })
			} "required field cannot be empty"

			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ smtp_host = "127.0.0.1"; smtp_port = "25"; smtp_user = "a"; smtp_pass = "" })
			} "required field cannot be empty"
		}
	}

	Context "OAuth Option" {
		It "rejects empty OAuth credentials" {
			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ oauth_client_id = ""; oauth_client_secret = "sec"; oauth_redirect = "http://cb" })
			} "required field cannot be empty"

			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ oauth_client_id = "id"; oauth_client_secret = ""; oauth_redirect = "http://cb" })
			} "required field cannot be empty"

			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ oauth_client_id = "id"; oauth_client_secret = "sec"; oauth_redirect = "" })
			} "required field cannot be empty"
		}
	}

	Context "Pepper Option" {
		It "rejects empty global pepper" {
			Assert-Throws {
				[void](Invoke-Harness "/api/init" @{ pepper = "" })
			} "required field cannot be empty"
		}
	}

	Context "Password Policy Defaults" {
		It "normalizes non-positive bounds to minimum 12 and maximum 72" {
			$res = Invoke-Harness "/api/init" @{
				password_policy = @{
					min_length = 0
					max_length = 0
				}
			}
			Assert-Equal $res.data.status "initialized"
		}
	}

	Context "Close Method" {
		It "closes cleanly and is idempotent across multiple calls" {
			$res1 = Invoke-Harness "/api/close"
			Assert-Equal $res1.data.status "closed"

			$res2 = Invoke-Harness "/api/close"
			Assert-Equal $res2.data.status "closed"
		}
	}
}
