# 05-OTP-Email.Tests.ps1
# Comprehensive tests for OTP lifecycle, verification, and email delivery using DummySMTPServer.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"
. "$PSScriptRoot/DummySMTPServer.ps1"

Describe "OTP Lifecycle and Dummy SMTP Server Delivery" {
	Context "End-to-End Delivery and Verification" {
		It "sends OTP through dummy SMTP server, captures code, and verifies successfully" {
			$smtp = Start-DummySMTPServer -RequireAuth -ExpectedUsername "mailer@auth.test" -ExpectedPassword "mailer-secret"
			try {
				[void](Reset-HarnessState -Storage "mock" `
					-SMTPHost $smtp.Host `
					-SMTPPort $smtp.Port `
					-SMTPUser "mailer@auth.test" `
					-SMTPPass "mailer-secret")
				[void](Invoke-Harness "/api/mock/reset")

				$targetEmail = "dev@example.com"

				# 1. Send OTP
				$sendRes = Invoke-Harness "/api/send-otp" @{ email = $targetEmail }
				Assert-Equal $sendRes.data.status "sent"

				# 2. Capture email on dummy SMTP server
				$received = $smtp.WaitEmail(3000)
				Assert-NotNull $received "Dummy SMTP server should receive email"
				Assert-Equal $received.From "mailer@auth.test"
				Assert-Equal $received.To[0] $targetEmail
				Assert-Equal $received.Subject "Your Verification Code"
				Assert-NotNull $received.OTP "OTP should be extracted from email body"
				Assert-Equal $received.OTP.Length 6 "Default OTP length is 6"

				# 3. Check OTPExists returns true
				$existsRes = Invoke-Harness "/api/otp-exists" @{ email = $targetEmail }
				Assert-True $existsRes.data.exists "OTP should exist prior to verification"

				# 4. Verify with the captured code
				$verifyRes = Invoke-Harness "/api/verify-otp" @{
					email = $targetEmail
					code  = $received.OTP
				}
				Assert-Equal $verifyRes.data.status "verified"

				# 5. OTP must be consumed (single-use): secondary verification fails
				Assert-Throws {
					[void](Invoke-Harness "/api/verify-otp" @{
						email = $targetEmail
						code  = $received.OTP
					})
				} "invalid otp code"

				# 6. OTPExists now returns false
				$existsAfter = Invoke-Harness "/api/otp-exists" @{ email = $targetEmail }
				Assert-False $existsAfter.data.exists "OTP should no longer exist after verification"
			} finally {
				$smtp.Stop()
			}
		}

		It "rejects incorrect OTP codes" {
			$smtp = Start-DummySMTPServer
			try {
				[void](Reset-HarnessState -Storage "mock" -SMTPHost $smtp.Host -SMTPPort $smtp.Port -SMTPUser "a@b.com" -SMTPPass "pass")
				[void](Invoke-Harness "/api/mock/reset")

				$email = "user@test.com"
				[void](Invoke-Harness "/api/send-otp" @{ email = $email })
				$received = $smtp.WaitEmail(2000)
				Assert-NotNull $received

				# Supply incorrect code
				Assert-Throws {
					[void](Invoke-Harness "/api/verify-otp" @{
						email = $email
						code  = "000000"
					})
				} "invalid otp code"
			} finally {
				$smtp.Stop()
			}
		}

		It "handles expired OTP codes" {
			$smtp = Start-DummySMTPServer
			try {
				# Set OTP expiry to 1 millisecond
				[void](Reset-HarnessState -Storage "mock" `
					-SMTPHost $smtp.Host `
					-SMTPPort $smtp.Port `
					-SMTPUser "a@b.com" `
					-SMTPPass "pass" `
					-OTPExpiry "1ms")
				[void](Invoke-Harness "/api/mock/reset")

				$email = "expiretest@test.com"
				[void](Invoke-Harness "/api/send-otp" @{ email = $email })
				$received = $smtp.WaitEmail(2000)
				Assert-NotNull $received

				# Wait for 50ms so OTP expires
				[System.Threading.Thread]::Sleep(50)

				Assert-Throws {
					[void](Invoke-Harness "/api/verify-otp" @{
						email = $email
						code  = $received.OTP
					})
				} "otp expired"
			} finally {
				$smtp.Stop()
			}
		}
	}

	Context "SendOTP Edge Cases and Faults" {
		It "rejects invalid email formats" {
			$smtp = Start-DummySMTPServer
			try {
				[void](Reset-HarnessState -Storage "mock" -SMTPHost $smtp.Host -SMTPPort $smtp.Port -SMTPUser "a@b.com" -SMTPPass "pass")
				Assert-Throws {
					[void](Invoke-Harness "/api/send-otp" @{ email = "not-an-email" })
				} "invalid email format"

				Assert-Throws {
					[void](Invoke-Harness "/api/verify-otp" @{ email = "not-an-email"; code = "123456" })
				} "invalid email format"

				Assert-Throws {
					[void](Invoke-Harness "/api/otp-exists" @{ email = "not-an-email" })
				} "invalid email format"
			} finally {
				$smtp.Stop()
			}
		}

		It "fails when SMTP server rejects authentication credentials" {
			$smtp = Start-DummySMTPServer -RequireAuth -ExpectedUsername "valid-user" -ExpectedPassword "valid-pass"
			try {
				# Provide wrong password to Auth
				[void](Reset-HarnessState -Storage "mock" `
					-SMTPHost $smtp.Host `
					-SMTPPort $smtp.Port `
					-SMTPUser "valid-user" `
					-SMTPPass "wrong-pass")

				Assert-Throws {
					[void](Invoke-Harness "/api/send-otp" @{ email = "user@test.com" })
				} "failed to send email"
			} finally {
				$smtp.Stop()
			}
		}

		It "fails when SMTP server is unreachable" {
			# Unbound random port
			[void](Reset-HarnessState -Storage "mock" `
				-SMTPHost "127.0.0.1" `
				-SMTPPort "59999" `
				-SMTPUser "user" `
				-SMTPPass "pass")

			Assert-Throws {
				[void](Invoke-Harness "/api/send-otp" @{ email = "user@test.com" })
			} "failed to send email"
		}
	}

	Context "ListActiveOTPs" {
		It "lists currently active unexpired OTP emails" {
			$smtp = Start-DummySMTPServer
			try {
				[void](Reset-HarnessState -Storage "mock" `
					-SMTPHost $smtp.Host `
					-SMTPPort $smtp.Port `
					-SMTPUser "a@b.com" `
					-SMTPPass "pass" `
					-OTPExpiry "5m")
				[void](Invoke-Harness "/api/mock/reset")

				[void](Invoke-Harness "/api/send-otp" @{ email = "active1@test.com" })
				[void](Invoke-Harness "/api/send-otp" @{ email = "active2@test.com" })

				$res = Invoke-Harness "/api/list-active-otps?limit=10&offset=0"
				Assert-True ($res.data.Count -ge 2) "Should list at least two active OTPs"
			} finally {
				$smtp.Stop()
			}
		}
	}

	Context "Direct email.Send Function" {
		It "successfully delivers a raw email to the dummy server" {
			$smtp = Start-DummySMTPServer -RequireAuth -ExpectedUsername "mailer@gcet.test" -ExpectedPassword "pass"
			try {
				$res = Invoke-Harness "/api/email/send" @{
					host       = $smtp.Host
					port       = "$($smtp.Port)"
					from_email = "mailer@gcet.test"
					password   = "pass"
					to_email   = "recipient@gcet.test"
					subject    = "Direct Email Test"
					body       = "Direct body content"
				}
				Assert-Equal $res.data.status "sent"

				$received = $smtp.WaitEmail(2000)
				Assert-NotNull $received
				Assert-Equal $received.From "mailer@gcet.test"
				Assert-Equal $received.To[0] "recipient@gcet.test"
				Assert-Equal $received.Subject "Direct Email Test"
			} finally {
				$smtp.Stop()
			}
		}
	}
}
