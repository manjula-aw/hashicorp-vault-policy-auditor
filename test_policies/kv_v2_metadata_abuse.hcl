# HIGH: Metadata tampering across secrets
path "secret/metadata/*" { capabilities = ["create", "update", "delete"] }
# HIGH: Version destruction
path "secret/destroy/*" { capabilities = ["update"] }