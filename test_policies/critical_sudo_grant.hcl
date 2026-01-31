# DANGER: Grants sudo on a secret engine
path "secret/data/payment_gateway/keys" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# DANGER: Grants sudo on an auth method
path "sys/auth/approle/login" {
  capabilities = ["create", "read", "sudo"]
}
