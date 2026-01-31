# CRITICAL: Root CA generation
path "pki/root/generate/*" { capabilities = ["create", "update"] }
# CRITICAL: Certificate signing
path "pki/sign/*" { capabilities = ["update"] }
# HIGH: Revocation control
path "pki/revoke" { capabilities = ["update"] }