# 03-Users.Tests.ps1
# Tests for User lifecycle, credentials, and password policies in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"

Describe "User Management and Password Policies" {
	Context "Password Policy Validation" {
		It "enforces default minimum length of 12 characters" {
			[void](Reset-HarnessState -Storage "mock")
			Assert-Throws {
				[void](Invoke-Harness "/api/register-user" @{
					username = "user1@example.com"
					password = "Short1!"
				})
			} "password must be at least 12 characters"
		}

		It "enforces configured maximum length" {
			[void](Reset-HarnessState -Storage "mock" -Policy @{
				min_length = 8
				max_length = 16
			})
			Assert-Throws {
				[void](Invoke-Harness "/api/register-user" @{
					username = "user2@example.com"
					password = "ThisPasswordIsWayTooLong123!"
				})
			} "password cannot exceed 16 characters"
		}

		It "enforces uppercase character requirement" {
			[void](Reset-HarnessState -Storage "mock" -Policy @{
				min_length        = 8
				max_length        = 72
				require_uppercase = $true
			})
			Assert-Throws {
				[void](Invoke-Harness "/api/register-user" @{
					username = "user3@example.com"
					password = "alllowercasepassword1!"
				})
			} "password must contain at least one uppercase letter"
		}

		It "enforces number requirement" {
			[void](Reset-HarnessState -Storage "mock" -Policy @{
				min_length     = 8
				max_length     = 72
				require_number = $true
			})
			Assert-Throws {
				[void](Invoke-Harness "/api/register-user" @{
					username = "user4@example.com"
					password = "PasswordWithoutNumbers!"
				})
			} "password must contain at least one number"
		}

		It "enforces special character requirement" {
			[void](Reset-HarnessState -Storage "mock" -Policy @{
				min_length      = 8
				max_length      = 72
				require_special = $true
			})
			Assert-Throws {
				[void](Invoke-Harness "/api/register-user" @{
					username = "user5@example.com"
					password = "PasswordWithNumbers1234"
				})
			} "password must contain at least one special character"
		}
	}

	Context "Registration and Authentication" {
		It "registers a user and verifies login credentials" {
			[void](Reset-HarnessState -Storage "mock")
			[void](Invoke-Harness "/api/mock/reset")

			$email = "alice@example.com"
			$password = "CorrectP@ssword123!"

			$reg = Invoke-Harness "/api/register-user" @{
				username = $email
				password = $password
			}
			Assert-Equal $reg.data.status "registered"

			$login = Invoke-Harness "/api/login-user" @{
				username = $email
				password = $password
			}
			Assert-Equal $login.data.status "logged_in"
		}

		It "rejects duplicate user registrations" {
			$email = "alice@example.com"
			Assert-Throws {
				[void](Invoke-Harness "/api/register-user" @{
					username = $email
					password = "AnotherP@ssword123!"
				})
			} "user already exists"
		}

		It "rejects invalid passwords for existing users" {
			Assert-Throws {
				[void](Invoke-Harness "/api/login-user" @{
					username = "alice@example.com"
					password = "WrongP@ssword123!"
				})
			} "invalid credentials"
		}

		It "returns user not found for non-existent usernames" {
			Assert-Throws {
				[void](Invoke-Harness "/api/login-user" @{
					username = "nonexistent@example.com"
					password = "AnyP@ssword123!"
				})
			} "user not found"
		}
	}

	Context "Password Change" {
		It "updates a user password and enforces new credentials" {
			$email = "alice@example.com"
			$newPass = "BrandNewP@ssword456!"

			$res = Invoke-Harness "/api/change-pass" @{
				username     = $email
				new_password = $newPass
			}
			Assert-Equal $res.data.status "password_changed"

			# Old password should now fail
			Assert-Throws {
				[void](Invoke-Harness "/api/login-user" @{
					username = $email
					password = "CorrectP@ssword123!"
				})
			} "invalid credentials"

			# New password succeeds
			$login = Invoke-Harness "/api/login-user" @{
				username = $email
				password = $newPass
			}
			Assert-Equal $login.data.status "logged_in"
		}

		It "returns user not found when changing password for non-existent user" {
			Assert-Throws {
				[void](Invoke-Harness "/api/change-pass" @{
					username     = "ghost@example.com"
					new_password = "SomePassword123!"
				})
			} "user not found"
		}
	}

	Context "User Existence and Queries" {
		It "validates user existence with valid and invalid email addresses" {
			$exists1 = Invoke-Harness "/api/user-exists" @{ email = "alice@example.com" }
			Assert-True $exists1.data.exists "alice@example.com should exist"

			$exists2 = Invoke-Harness "/api/user-exists" @{ email = "nobody@example.com" }
			Assert-False $exists2.data.exists "nobody@example.com should not exist"

			Assert-Throws {
				[void](Invoke-Harness "/api/user-exists" @{ email = "not-an-email" })
			} "invalid email format"
		}

		It "returns paginated user lists" {
			[void](Invoke-Harness "/api/register-user" @{ username = "bob@example.com"; password = "PasswordForBob1!" })
			[void](Invoke-Harness "/api/register-user" @{ username = "charlie@example.com"; password = "PasswordForCharlie1!" })

			$list = Invoke-Harness "/api/list-users?limit=2&offset=0"
			Assert-Equal $list.data.Count 2
		}
	}

	Context "User Deletion" {
		It "completely deletes a user and revokes access" {
			$email = "alice@example.com"
			$del = Invoke-Harness "/api/delete-user" @{ username = $email }
			Assert-Equal $del.data.status "deleted"

			$exists = Invoke-Harness "/api/user-exists" @{ email = $email }
			Assert-False $exists.data.exists "Deleted user should not exist"

			Assert-Throws {
				[void](Invoke-Harness "/api/login-user" @{
					username = $email
					password = "BrandNewP@ssword456!"
				})
			} "user not found"
		}
	}
}
