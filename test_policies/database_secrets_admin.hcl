# HIGH: Database credential generation
path "database/creds/*" { capabilities = ["read"] }
# CRITICAL: Database role manipulation
path "database/roles/*" { capabilities = ["create", "update", "delete"] }