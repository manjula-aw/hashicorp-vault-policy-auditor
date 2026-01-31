# CRITICAL: Token creation
path "auth/token/create" { capabilities = ["create", "update"] }
# HIGH: Token inspection
path "auth/token/lookup" { capabilities = ["read"] }
# HIGH: Identity modification
path "identity/*" { capabilities = ["create", "update", "delete", "list"] }