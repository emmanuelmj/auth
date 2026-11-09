# 08-RBAC.Tests.ps1
# Tests for Roles, Spaces, and Permissions (RBAC) in PowerShell 7.
# Uses tab indentation.

. "$PSScriptRoot/TestFramework.ps1"
. "$PSScriptRoot/HarnessClient.ps1"

Describe "Roles, Spaces, and Permissions (RBAC)" {
	Context "Role Management" {
		It "creates and deletes organizational roles" {
			[void](Reset-HarnessState -Storage "mock")
			[void](Invoke-Harness "/api/mock/reset")

			$role = "admin"
			$resCreate = Invoke-Harness "/api/create-role" @{ name = $role }
			Assert-Equal $resCreate.data.status "created"

			# Duplicate role rejected
			Assert-Throws {
				[void](Invoke-Harness "/api/create-role" @{ name = $role })
			} "role already exists"

			$resDelete = Invoke-Harness "/api/delete-role" @{ name = $role }
			Assert-Equal $resDelete.data.status "deleted"
		}
	}

	Context "Space Management" {
		It "creates and deletes spaces with authority levels" {
			$space = "engineering"
			$resCreate = Invoke-Harness "/api/create-space" @{ name = $space; authority = 10 }
			Assert-Equal $resCreate.data.status "created"

			# Duplicate space rejected
			Assert-Throws {
				[void](Invoke-Harness "/api/create-space" @{ name = $space; authority = 10 })
			} "space already exists"

			$resDelete = Invoke-Harness "/api/delete-space" @{ name = $space }
			Assert-Equal $resDelete.data.status "deleted"
		}
	}

	Context "Permissions Assignment and Verification" {
		It "assigns and validates user permissions across spaces and roles" {
			# Setup prerequisites
			$user = "rbacuser@test.com"
			$space = "ops"
			$role = "operator"

			[void](Invoke-Harness "/api/register-user" @{ username = $user; password = "Password12345!" })
			[void](Invoke-Harness "/api/create-space" @{ name = $space; authority = 5 })
			[void](Invoke-Harness "/api/create-role" @{ name = $role })

			# Assign permission
			$permRes = Invoke-Harness "/api/create-permission" @{
				username   = $user
				space_name = $space
				role       = $role
			}
			Assert-Equal $permRes.data.status "created"

			# Check permission granted
			$checkRes = Invoke-Harness "/api/check-permission" @{
				username   = $user
				space_name = $space
				role       = $role
			}
			Assert-Equal $checkRes.data.status "authorized"

			# Check different unassigned role returns unauthorized
			Assert-Throws {
				[void](Invoke-Harness "/api/check-permission" @{
					username   = $user
					space_name = $space
					role       = "viewer"
				})
			} "invalid credentials"

			# Delete permission
			$delPerm = Invoke-Harness "/api/delete-permission" @{
				username   = $user
				space_name = $space
				role       = $role
			}
			Assert-Equal $delPerm.data.status "deleted"

			# Now unauthorized
			Assert-Throws {
				[void](Invoke-Harness "/api/check-permission" @{
					username   = $user
					space_name = $space
					role       = $role
				})
			} "invalid credentials"
		}

		It "rejects permission creation for non-existent entities" {
			Assert-Throws {
				[void](Invoke-Harness "/api/create-permission" @{
					username   = "nonexistent@test.com"
					space_name = "ops"
					role       = "operator"
				})
			} "user not found"

			Assert-Throws {
				[void](Invoke-Harness "/api/create-permission" @{
					username   = "rbacuser@test.com"
					space_name = "nonexistent-space"
					role       = "operator"
				})
			} "space not found"

			Assert-Throws {
				[void](Invoke-Harness "/api/create-permission" @{
					username   = "rbacuser@test.com"
					space_name = "ops"
					role       = "nonexistent-role"
				})
			} "role not found"
		}
	}

	Context "Cascade Deletion Semantics" {
		It "cascades permission deletion when a space or user is removed" {
			$user = "cascadeuser@test.com"
			$space = "finance"
			$role = "auditor"

			[void](Invoke-Harness "/api/register-user" @{ username = $user; password = "Password12345!" })
			[void](Invoke-Harness "/api/create-space" @{ name = $space; authority = 8 })
			[void](Invoke-Harness "/api/create-role" @{ name = $role })
			[void](Invoke-Harness "/api/create-permission" @{ username = $user; space_name = $space; role = $role })

			# Verify initial permission
			$check1 = Invoke-Harness "/api/check-permission" @{ username = $user; space_name = $space; role = $role }
			Assert-Equal $check1.data.status "authorized"

			# Delete space
			[void](Invoke-Harness "/api/delete-space" @{ name = $space })

			# Permission must now be revoked
			Assert-Throws {
				[void](Invoke-Harness "/api/check-permission" @{ username = $user; space_name = $space; role = $role })
			} "invalid credentials"
		}
	}
}
