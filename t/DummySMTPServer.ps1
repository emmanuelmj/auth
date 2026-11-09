# DummySMTPServer.ps1
# Pure PowerShell 7 RFC 5321 in-process dummy SMTP server for testing OTP & email flows.
# Uses tab indentation.

function Start-DummySMTPServer {
	[CmdletBinding()]
	param(
		[int]$Port = 0,
		[switch]$RequireAuth,
		[string]$ExpectedUsername = "",
		[string]$ExpectedPassword = "",
		[switch]$RejectAuth,
		[switch]$RejectRecipient,
		[switch]$RejectData,
		[switch]$DropConnection
	)

	$sync = [hashtable]::Synchronized(@{
		Done             = $false
		Port             = $Port
		Host             = "127.0.0.1"
		RequireAuth      = [bool]$RequireAuth
		ExpectedUsername = $ExpectedUsername
		ExpectedPassword = $ExpectedPassword
		RejectAuth       = [bool]$RejectAuth
		RejectRecipient  = [bool]$RejectRecipient
		RejectData       = [bool]$RejectData
		DropConnection   = [bool]$DropConnection
		Emails           = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
		NewEmailEvent    = [System.Threading.ManualResetEventSlim]::new($false)
	})

	$rs = [runspacefactory]::CreateRunspace()
	$rs.Open()
	$rs.SessionStateProxy.SetVariable("sync", $sync)

	$ps = [powershell]::Create()
	$ps.Runspace = $rs

	[void]$ps.AddScript({
		$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $sync.Port)
		$listener.Start()
		$sync.Port = $listener.LocalEndpoint.Port
		$sync.Listener = $listener

		while (-not $sync.Done) {
			try {
				if (-not $listener.Pending()) {
					[System.Threading.Thread]::Sleep(10)
					continue
				}

				$client = $listener.AcceptTcpClient()
				$client.ReceiveTimeout = 3000
				$client.SendTimeout = 3000
				if ($sync.DropConnection) {
					$client.Close()
					continue
				}

				# Handle SMTP conversation
				$stream = $client.GetStream()
				$reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
				$writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::UTF8)
				$writer.NewLine = "`r`n"

				# 220 banner
				$writer.WriteLine("220 127.0.0.1 Simple Mail Transfer Service Ready")
				$writer.Flush()

				$from = ""
				$to = [System.Collections.Generic.List[string]]::new()
				$authenticated = (-not $sync.RequireAuth)

				while ($client.Connected -and -not $sync.Done) {
					$line = $reader.ReadLine()
					if ($null -eq $line) { break }
					$line = $line.Trim()
					if ($line.Length -eq 0) { continue }

					$parts = $line.Split(' ', 2)
					$cmd = $parts[0].ToUpperInvariant()
					$arg = if ($parts.Length -gt 1) { $parts[1] } else { "" }

					switch ($cmd) {
						"EHLO" {
							$writer.WriteLine("250-127.0.0.1 greets you")
							$writer.WriteLine("250-AUTH PLAIN")
							$writer.WriteLine("250-8BITMIME")
							$writer.WriteLine("250 OK")
							$writer.Flush()
						}
						"HELO" {
							$writer.WriteLine("250 127.0.0.1 greets you")
							$writer.Flush()
						}
						"AUTH" {
							if ($sync.RejectAuth) {
								$writer.WriteLine("535 5.7.8 Authentication credentials invalid")
								$writer.Flush()
								continue
							}

							$authParts = $arg.Split(' ', 2)
							$mech = $authParts[0].ToUpperInvariant()
							$rawToken = if ($authParts.Length -gt 1) { $authParts[1] } else { "" }

							if ([string]::IsNullOrWhiteSpace($rawToken)) {
								$writer.WriteLine("334 ")
								$writer.Flush()
								$rawToken = $reader.ReadLine()
								if ($null -eq $rawToken) { break }
								$rawToken = $rawToken.Trim()
							}

							if ($mech -ne "PLAIN") {
								$writer.WriteLine("504 5.5.4 Unrecognized authentication type")
								$writer.Flush()
								continue
							}

							try {
								$bytes = [System.Convert]::FromBase64String($rawToken)
								$partsDecoded = [System.Text.Encoding]::UTF8.GetString($bytes).Split("`0")
								$user = ""
								$pass = ""
								if ($partsDecoded.Length -ge 3) {
									$user = $partsDecoded[1]
									$pass = $partsDecoded[2]
								} elseif ($partsDecoded.Length -eq 2) {
									$user = $partsDecoded[0]
									$pass = $partsDecoded[1]
								}

								if ($sync.RequireAuth) {
									if ($sync.ExpectedUsername -and ($user -ne $sync.ExpectedUsername)) {
										$writer.WriteLine("535 5.7.8 Authentication credentials invalid")
										$writer.Flush()
										continue
									}
									if ($sync.ExpectedPassword -and ($pass -ne $sync.ExpectedPassword)) {
										$writer.WriteLine("535 5.7.8 Authentication credentials invalid")
										$writer.Flush()
										continue
									}
								}

								$authenticated = $true
								$writer.WriteLine("235 2.7.0 Authentication successful")
								$writer.Flush()
							} catch {
								$writer.WriteLine("501 5.5.2 Cannot decode authentication response")
								$writer.Flush()
							}
						}
						"MAIL" {
							if (-not $authenticated) {
								$writer.WriteLine("530 5.7.0 Authentication required")
								$writer.Flush()
								continue
							}

							$raw = $arg
							if ($raw.ToUpperInvariant().StartsWith("FROM:")) {
								$raw = $raw.Substring(5).Trim()
							}
							if ($raw -match "<([^>]+)>") {
								$from = $Matches[1]
							} else {
								$from = $raw.Split(' ')[0]
							}
							$to.Clear()
							$writer.WriteLine("250 2.1.0 Sender OK")
							$writer.Flush()
						}
						"RCPT" {
							if (-not $authenticated) {
								$writer.WriteLine("530 5.7.0 Authentication required")
								$writer.Flush()
								continue
							}
							if ($sync.RejectRecipient) {
								$writer.WriteLine("550 5.1.1 User unknown")
								$writer.Flush()
								continue
							}

							$raw = $arg
							if ($raw.ToUpperInvariant().StartsWith("TO:")) {
								$raw = $raw.Substring(3).Trim()
							}
							$rcpt = if ($raw -match "<([^>]+)>") { $Matches[1] } else { $raw.Split(' ')[0] }
							$to.Add($rcpt)
							$writer.WriteLine("250 2.1.5 Recipient OK")
							$writer.Flush()
						}
						"DATA" {
							if (-not $authenticated) {
								$writer.WriteLine("530 5.7.0 Authentication required")
								$writer.Flush()
								continue
							}
							if ($sync.RejectData) {
								$writer.WriteLine("554 5.5.0 Transaction failed")
								$writer.Flush()
								continue
							}

							$writer.WriteLine("354 Start mail input; end with <CRLF>.<CRLF>")
							$writer.Flush()

							$sb = [System.Text.StringBuilder]::new()
							while ($true) {
								$dataLine = $reader.ReadLine()
								if ($null -eq $dataLine -or $dataLine -eq ".") {
									break
								}
								if ($dataLine.StartsWith("..")) {
									$dataLine = $dataLine.Substring(1)
								}
								[void]$sb.AppendLine($dataLine)
							}

							$rawContent = $sb.ToString()
							$subject = ""
							$body = ""
							$otp = ""

							if ($rawContent -match "(?m)^Subject:\s*(.*)$") {
								$subject = $Matches[1].Trim()
							}
							if ($rawContent -match "Your OTP is:\s*([0-9a-zA-Z]+)") {
								$otp = $Matches[1].Trim()
							}

							$lines = $rawContent -split "\r?\n"
							$headerDone = $false
							$bodyBuilder = [System.Text.StringBuilder]::new()
							foreach ($l in $lines) {
								if (-not $headerDone) {
									if ($l.Trim().Length -eq 0) {
										$headerDone = $true
									}
								} else {
									[void]$bodyBuilder.AppendLine($l)
								}
							}
							$body = $bodyBuilder.ToString().TrimEnd()

							$emailRecord = [PSCustomObject]@{
								From    = $from
								To      = $to.ToArray()
								Subject = $subject
								Body    = $body
								Raw     = $rawContent
								OTP     = $otp
								Date    = [DateTime]::UtcNow
							}

							[void]$sync.Emails.Add($emailRecord)
							$sync.NewEmailEvent.Set()

							$writer.WriteLine("250 2.0.0 OK: queued")
							$writer.Flush()
						}
						"RSET" {
							$from = ""
							$to.Clear()
							$writer.WriteLine("250 2.0.0 OK")
							$writer.Flush()
						}
						"NOOP" {
							$writer.WriteLine("250 2.0.0 OK")
							$writer.Flush()
						}
						"QUIT" {
							$writer.WriteLine("221 2.0.0 Service closing transmission channel")
							$writer.Flush()
							break
						}
						default {
							$writer.WriteLine("500 5.5.2 Syntax error, command unrecognized")
							$writer.Flush()
						}
					}
				}
				$client.Close()
			} catch {
				# Listener stopped or client disconnected
			}
		}

		try { $listener.Stop() } catch {}
	})

	$asyncResult = $ps.BeginInvoke()

	$timeout = [DateTime]::UtcNow.AddSeconds(5)
	while ($sync.Port -eq 0 -and [DateTime]::UtcNow -lt $timeout) {
		[System.Threading.Thread]::Sleep(10)
	}

	if ($sync.Port -eq 0) {
		$sync.Done = $true
		$ps.Dispose()
		$rs.Close()
		throw "Failed to start DummySMTPServer within timeout"
	}

	$serverObj = [PSCustomObject]@{
		Host            = "127.0.0.1"
		Port            = $sync.Port
		Addr            = "127.0.0.1:$($sync.Port)"
		_Sync           = $sync
		_PS             = $ps
		_RS             = $rs
		_Async          = $asyncResult
	}

	$serverObj | Add-Member -MemberType ScriptMethod -Name "GetEmails" -Value {
		return @($this._Sync.Emails.ToArray())
	}

	$serverObj | Add-Member -MemberType ScriptMethod -Name "GetLastEmail" -Value {
		$arr = $this._Sync.Emails
		if ($arr.Count -eq 0) { return $null }
		return $arr[$arr.Count - 1]
	}

	$serverObj | Add-Member -MemberType ScriptMethod -Name "Reset" -Value {
		$this._Sync.Emails.Clear()
		$this._Sync.NewEmailEvent.Reset()
	}

	$serverObj | Add-Member -MemberType ScriptMethod -Name "WaitEmail" -Value {
		param([int]$TimeoutMs = 5000)
		$sw = [System.Diagnostics.Stopwatch]::StartNew()
		while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
			if ($this._Sync.Emails.Count -gt 0) {
				return $this._Sync.Emails[$this._Sync.Emails.Count - 1]
			}
			if ($this._Sync.NewEmailEvent.Wait(100)) {
				$this._Sync.NewEmailEvent.Reset()
				if ($this._Sync.Emails.Count -gt 0) {
					return $this._Sync.Emails[$this._Sync.Emails.Count - 1]
				}
			}
		}
		return $null
	}

	$serverObj | Add-Member -MemberType ScriptMethod -Name "Stop" -Value {
		if (-not $this._Sync.Done) {
			$this._Sync.Done = $true
			try { $this._Sync.Listener.Stop() } catch {}
			try { $this._PS.Stop() } catch {}
			try { $this._PS.Dispose() } catch {}
			try { $this._RS.Close() } catch {}
		}
	}

	return $serverObj
}

function Stop-DummySMTPServer {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		$Server
	)
	if ($null -ne $Server) {
		$Server.Stop()
	}
}
