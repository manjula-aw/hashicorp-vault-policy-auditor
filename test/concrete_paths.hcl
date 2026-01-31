# This specific path should also be matched by "secret/data/dev/*" from file lazy_admin_wildcard.hcl
path "secret/data/dev/app-config" {
  capabilities = ["read"]
}

# This specific path matches the wildcard in file lazy_admin_wildcard.hcl
path "secret/data/dev/db-password" {
  capabilities = ["read", "update"]
}
