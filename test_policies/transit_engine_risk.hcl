# CRITICAL: Key management
path "transit/keys/*" { capabilities = ["create", "update", "delete", "list"] }
# HIGH: Encryption and signing
path "transit/encrypt/*" { capabilities = ["update"] }
path "transit/sign/*" { capabilities = ["update"] }