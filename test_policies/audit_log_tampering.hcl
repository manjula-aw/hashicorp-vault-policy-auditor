# CRITICAL: Enable/disable audit devices
path "sys/audit/*" { capabilities = ["create", "update", "delete"] }
# HIGH: Audit hash access
path "sys/audit-hash/*" { capabilities = ["read"] }