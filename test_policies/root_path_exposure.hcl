# HIGH RISK: Applies to the entire Vault instance
path "*" {
  capabilities = ["read", "list"]
}

# HIGH RISK: Another syntax for root level access
path "/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
