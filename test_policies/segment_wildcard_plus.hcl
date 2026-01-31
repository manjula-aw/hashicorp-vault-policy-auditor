# MEDIUM: Segment wildcard
path "secret/data/+/config" { capabilities = ["read", "list"] }
# HIGH: Metadata write with segment wildcard
path "secret/metadata/+" { capabilities = ["update", "delete"] }