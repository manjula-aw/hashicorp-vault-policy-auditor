# Matches secret/data/app1/config, secret/data/app2/config
# But does NOT match secret/data/app1/service/config
path "secret/data/+/config" {
  capabilities = ["read", "list"]
}

# Granting write access to metadata only
path "secret/metadata/+" {
  capabilities = ["create", "update", "delete"]
}
