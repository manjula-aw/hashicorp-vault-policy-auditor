# CRITICAL: Full control over mounts
path "sys/mounts/*" {
  capabilities = ["create", "update", "delete", "list"]
}
# HIGH: Read system leadership and health
path "sys/leader" { capabilities = ["read"] }
path "sys/health" { capabilities = ["read"] }