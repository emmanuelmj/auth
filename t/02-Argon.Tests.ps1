# 02-Argon.Tests.ps1
# Tests for Argon2 parameters and password hashing in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"

Describe "Argon2 Parameters and Hashing" {
	Context "DefaultSaltParameters Boundaries" {
		It "rejects zero time iterations" {
			[void](Reset-HarnessState)
			Assert-Throws {
				[void](Invoke-Harness "/api/default-salt-params" @{
					time    = 0
					memory  = 65536
					threads = 1
					key_len = 32
				})
			} "time \(iterations\) cannot be zero"
		}

		It "rejects memory below 32MB" {
			Assert-Throws {
				[void](Invoke-Harness "/api/default-salt-params" @{
					time    = 3
					memory  = 16384
					threads = 1
					key_len = 32
				})
			} "memory too low: must be at least 32MB"
		}

		It "rejects zero threads" {
			Assert-Throws {
				[void](Invoke-Harness "/api/default-salt-params" @{
					time    = 3
					memory  = 65536
					threads = 0
					key_len = 32
				})
			} "threads cannot be zero"
		}

		It "rejects key length below 16 bytes" {
			Assert-Throws {
				[void](Invoke-Harness "/api/default-salt-params" @{
					time    = 3
					memory  = 65536
					threads = 1
					key_len = 15
				})
			} "key length too small: must be at least 16 bytes"
		}

		It "accepts valid boundary and standard parameters" {
			$res1 = Invoke-Harness "/api/default-salt-params" @{
				time    = 1
				memory  = 32768
				threads = 1
				key_len = 16
			}
			Assert-Equal $res1.data.status "updated"

			$res2 = Invoke-Harness "/api/default-salt-params" @{
				time    = 3
				memory  = 65536
				threads = 2
				key_len = 32
			}
			Assert-Equal $res2.data.status "updated"
		}
	}

	Context "HashPassword Edge Cases" {
		It "rejects salts shorter than 16 bytes" {
			[void](Reset-HarnessState -Pepper "test-pepper-minimum-32-bytes-long-key!")
			Assert-Throws {
				[void](Invoke-Harness "/api/hash-password" @{
					password = "ValidPassword123!"
					salt     = "short-salt"
				})
			} "salt too short"
		}

		It "generates deterministic hashes for identical inputs" {
			$salt = "0123456789abcdef"
			$res1 = Invoke-Harness "/api/hash-password" @{
				password = "TestP@ssword123!"
				salt     = $salt
			}
			$res2 = Invoke-Harness "/api/hash-password" @{
				password = "TestP@ssword123!"
				salt     = $salt
			}
			Assert-NotNull $res1.data.hash
			Assert-Equal $res1.data.hash $res2.data.hash "Identical inputs should yield identical hashes"
		}

		It "produces different hashes when salt differs" {
			$salt1 = "0123456789abcdef"
			$salt2 = "fedcba9876543210"
			$res1 = Invoke-Harness "/api/hash-password" @{
				password = "TestP@ssword123!"
				salt     = $salt1
			}
			$res2 = Invoke-Harness "/api/hash-password" @{
				password = "TestP@ssword123!"
				salt     = $salt2
			}
			Assert-True ($res1.data.hash -ne $res2.data.hash) "Different salts must produce different hashes"
		}

		It "produces different hashes when password differs" {
			$salt = "0123456789abcdef"
			$res1 = Invoke-Harness "/api/hash-password" @{
				password = "PasswordOne123!"
				salt     = $salt
			}
			$res2 = Invoke-Harness "/api/hash-password" @{
				password = "PasswordTwo123!"
				salt     = $salt
			}
			Assert-True ($res1.data.hash -ne $res2.data.hash) "Different passwords must produce different hashes"
		}

		It "allows hashing empty passwords when salt meets minimum length" {
			$salt = "0123456789abcdef"
			$res = Invoke-Harness "/api/hash-password" @{
				password = ""
				salt     = $salt
			}
			Assert-NotNull $res.data.hash
			Assert-True ($res.data.hash.Length -gt 0) "Empty password should still hash successfully"
		}

		It "verifies that pepper alters the final hash" {
			$salt = "0123456789abcdef"
			$pwd = "ConsistentP@ssword123!"

			[void](Reset-HarnessState -Pepper "first-pepper-minimum-32-bytes-long!")
			$resWithPepper = Invoke-Harness "/api/hash-password" @{
				password = $pwd
				salt     = $salt
			}

			[void](Reset-HarnessState -Pepper "different-pepper-minimum-32-bytes-long!")
			$resDiffPepper = Invoke-Harness "/api/hash-password" @{
				password = $pwd
				salt     = $salt
			}

			Assert-True ($resWithPepper.data.hash -ne $resDiffPepper.data.hash) "Different peppers must produce different hashes"
		}
	}
}
