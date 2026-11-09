# 00-DummySMTPServer.Tests.ps1
# Tests for DummySMTPServer.ps1 in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/DummySMTPServer.ps1"

Describe "DummySMTPServer Verification" {
	Context "Standard ESMTP Dialogue" {
		It "captures email headers, recipient, subject, and OTP code" {
			$srv = Start-DummySMTPServer -RequireAuth -ExpectedUsername "app@auth.test" -ExpectedPassword "app-secret"
			try {
				$client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", $srv.Port)
				$stream = $client.GetStream()
				$r = [System.IO.StreamReader]::new($stream)
				$w = [System.IO.StreamWriter]::new($stream)
				$w.NewLine = "`r`n"

				$banner = $r.ReadLine()
				Assert-Like $banner "^220" "Banner should start with 220"

				$w.WriteLine("EHLO localhost")
				$w.Flush()
				for ($i = 0; $i -lt 4; $i++) { [void]$r.ReadLine() }

				$authB64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("`0app@auth.test`0app-secret"))
				$w.WriteLine("AUTH PLAIN $authB64")
				$w.Flush()
				$authResp = $r.ReadLine()
				Assert-Like $authResp "^235" "Auth response should be 235"

				$w.WriteLine("MAIL FROM:<noreply@auth.test>")
				$w.Flush()
				$mailResp = $r.ReadLine()
				Assert-Like $mailResp "^250" "MAIL response should be 250"

				$w.WriteLine("RCPT TO:<user@destination.com>")
				$w.Flush()
				$rcptResp = $r.ReadLine()
				Assert-Like $rcptResp "^250" "RCPT response should be 250"

				$w.WriteLine("DATA")
				$w.Flush()
				$dataPrompt = $r.ReadLine()
				Assert-Like $dataPrompt "^354" "DATA prompt should be 354"

				$w.WriteLine("To: user@destination.com")
				$w.WriteLine("Subject: Your Verification Code")
				$w.WriteLine("")
				$w.WriteLine("Your OTP is: 951357")
				$w.WriteLine("Valid for 5 minutes.")
				$w.WriteLine(".")
				$w.Flush()
				$dataResp = $r.ReadLine()
				Assert-Like $dataResp "^250" "DATA completion should be 250"

				$w.WriteLine("QUIT")
				$w.Flush()
				$client.Close()

				$email = $srv.WaitEmail(3000)
				Assert-NotNull $email "Email should be captured"
				Assert-Equal $email.From "noreply@auth.test"
				Assert-Equal $email.To[0] "user@destination.com"
				Assert-Equal $email.Subject "Your Verification Code"
				Assert-Equal $email.OTP "951357"
			} finally {
				$srv.Stop()
			}
		}

		It "supports Reset to clear captured emails" {
			$srv = Start-DummySMTPServer
			try {
				$client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", $srv.Port)
				$stream = $client.GetStream()
				$r = [System.IO.StreamReader]::new($stream)
				$w = [System.IO.StreamWriter]::new($stream)
				$w.NewLine = "`r`n"
				[void]$r.ReadLine()

				$w.WriteLine("HELO localhost")
				$w.Flush()
				[void]$r.ReadLine()

				$w.WriteLine("MAIL FROM:<test@test.com>")
				$w.Flush()
				[void]$r.ReadLine()

				$w.WriteLine("RCPT TO:<recv@test.com>")
				$w.Flush()
				[void]$r.ReadLine()

				$w.WriteLine("DATA")
				$w.Flush()
				[void]$r.ReadLine()

				$w.WriteLine("Hello world")
				$w.WriteLine(".")
				$w.Flush()
				[void]$r.ReadLine()
				$client.Close()

				$email = $srv.WaitEmail(2000)
				Assert-NotNull $email
				Assert-Equal $srv.GetEmails().Count 1

				$srv.Reset()
				Assert-Equal $srv.GetEmails().Count 0
				Assert-Null $srv.GetLastEmail()
			} finally {
				$srv.Stop()
			}
		}
	}

	Context "Fault Injection" {
		It "rejects incorrect credentials when RequireAuth is enabled" {
			$srv = Start-DummySMTPServer -RequireAuth -ExpectedUsername "user" -ExpectedPassword "correct"
			try {
				$client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", $srv.Port)
				$stream = $client.GetStream()
				$r = [System.IO.StreamReader]::new($stream)
				$w = [System.IO.StreamWriter]::new($stream)
				$w.NewLine = "`r`n"
				[void]$r.ReadLine()

				$w.WriteLine("EHLO localhost")
				$w.Flush()
				for ($i = 0; $i -lt 4; $i++) { [void]$r.ReadLine() }

				$badAuthB64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("`0user`0wrong-pass"))
				$w.WriteLine("AUTH PLAIN $badAuthB64")
				$w.Flush()
				$resp = $r.ReadLine()
				Assert-Like $resp "^535" "Should return 535 credentials invalid"
				$client.Close()
			} finally {
				$srv.Stop()
			}
		}

		It "rejects recipient when RejectRecipient is enabled" {
			$srv = Start-DummySMTPServer -RejectRecipient
			try {
				$client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", $srv.Port)
				$stream = $client.GetStream()
				$r = [System.IO.StreamReader]::new($stream)
				$w = [System.IO.StreamWriter]::new($stream)
				$w.NewLine = "`r`n"
				[void]$r.ReadLine()

				$w.WriteLine("HELO localhost")
				$w.Flush()
				[void]$r.ReadLine()

				$w.WriteLine("MAIL FROM:<a@b.com>")
				$w.Flush()
				[void]$r.ReadLine()

				$w.WriteLine("RCPT TO:<bad@b.com>")
				$w.Flush()
				$resp = $r.ReadLine()
				Assert-Like $resp "^550" "Should return 550 recipient unknown"
				$client.Close()
			} finally {
				$srv.Stop()
			}
		}

		It "rejects transaction when RejectData is enabled" {
			$srv = Start-DummySMTPServer -RejectData
			try {
				$client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", $srv.Port)
				$stream = $client.GetStream()
				$r = [System.IO.StreamReader]::new($stream)
				$w = [System.IO.StreamWriter]::new($stream)
				$w.NewLine = "`r`n"
				[void]$r.ReadLine()

				$w.WriteLine("HELO localhost")
				$w.Flush()
				[void]$r.ReadLine()

				$w.WriteLine("MAIL FROM:<a@b.com>")
				$w.Flush()
				[void]$r.ReadLine()

				$w.WriteLine("RCPT TO:<c@d.com>")
				$w.Flush()
				[void]$r.ReadLine()

				$w.WriteLine("DATA")
				$w.Flush()
				$resp = $r.ReadLine()
				Assert-Like $resp "^554" "Should return 554 transaction failed"
				$client.Close()
			} finally {
				$srv.Stop()
			}
		}

		It "drops connections when DropConnection is enabled" {
			$srv = Start-DummySMTPServer -DropConnection
			try {
				$client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", $srv.Port)
				$stream = $client.GetStream()
				$r = [System.IO.StreamReader]::new($stream)
				$line = $r.ReadLine()
				Assert-Null $line "Stream should close immediately"
				$client.Close()
			} finally {
				$srv.Stop()
			}
		}
	}
}
