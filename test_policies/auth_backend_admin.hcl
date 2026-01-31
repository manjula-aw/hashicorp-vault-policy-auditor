# CRITICAL: Modify authentication backends
path "sys/auth/*" {
  capabilities = ["create", "update", "delete", "sudo"]
}
# HIGH: Auth login endpoint exposure
path "auth/approle/login" { capabilities = ["create", "read"] }