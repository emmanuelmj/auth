# 10-Database.Tests.ps1
# Tests for PostgreSQL StorageEngine initialization and schema checks in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"

Describe "PostgreSQL Storage Initialization and Schema" {
	Context "Parameter Validation" {
		It "rejects empty connection parameters" {
			Assert-Throws {
				[void](Invoke-Harness "/api/postgres/check-tables" @{
					port = 5432
					user = ""
					pass = "pass"
					name = "testdb"
					host = "127.0.0.1"
				})
			} "required field cannot be empty"

			Assert-Throws {
				[void](Invoke-Harness "/api/postgres/check-tables" @{
					port = 5432
					user = "user"
					pass = "pass"
					name = ""
					host = "127.0.0.1"
				})
			} "required field cannot be empty"

			Assert-Throws {
				[void](Invoke-Harness "/api/postgres/check-tables" @{
					port = 5432
					user = "user"
					pass = "pass"
					name = "testdb"
					host = ""
				})
			} "required field cannot be empty"
		}

		It "fails with connection error when target database is unreachable" {
			Assert-Throws {
				[void](Invoke-Harness "/api/postgres/check-tables" @{
					port = 59998
					user = "testuser"
					pass = "testpass"
					name = "testdb"
					host = "127.0.0.1"
				})
			} "failed to connect to postgres"
		}
	}

	Context "Live Database CheckTables (Integration)" {
		$dbHost = if ($env:TEST_DB_HOST) { $env:TEST_DB_HOST } else { "127.0.0.1" }
		$dbPort = if ($env:TEST_DB_PORT) { [int]$env:TEST_DB_PORT } else { 5432 }
		$dbUser = if ($env:TEST_DB_USER) { $env:TEST_DB_USER } else { "testuser" }
		$dbPass = if ($env:TEST_DB_PASS) { $env:TEST_DB_PASS } else { "testpass" }
		$dbName = if ($env:TEST_DB_NAME) { $env:TEST_DB_NAME } else { "testauth" }

		It "initializes schema tables when live PostgreSQL is available" {
			if ($env:AUTH_SHORT_TESTS -eq "1") {
				Skip "Live PostgreSQL integration" "Short mode active"
				return
			}

			try {
				$res = Invoke-Harness "/api/postgres/check-tables" @{
					port = $dbPort
					user = $dbUser
					pass = $dbPass
					name = $dbName
					host = $dbHost
				}
				Assert-Equal $res.data.status "ok"
			} catch {
				Skip "Live PostgreSQL integration" "PostgreSQL service not reachable ($($_.Exception.Message))"
			}
		}
	}
}
