# CRITICAL: Root wildcard read
path "*" { capabilities = ["read", "list"] }
# CRITICAL: Root wildcard write
path "/*" { capabilities = ["create", "read", "update", "delete", "list"] }