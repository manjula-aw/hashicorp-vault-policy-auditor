# HIGH RISK: Allows mounting/unmounting secret engines
path "sys/mounts/*" {
  capabilities = ["create", "update", "delete", "list"]
}

# HIGH RISK: Allows modifying authentication methods
path "sys/auth/*" {
  capabilities = ["create", "update", "sudo"]
}

# SAFE: Read-only access to system health is generally fine
path "sys/health" {
  capabilities = ["read"]
}
