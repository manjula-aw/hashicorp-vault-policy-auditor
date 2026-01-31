# DANGER: Grants full admin rights over the 'dev' folder
path "secret/data/dev/*" {
  capabilities = ["*"]
}

# DANGER: Grants full control over a specific database credential path
path "database/creds/readonly" {
  capabilities = ["*"]
}
