    variables = {
      DYNAMODB_TABLE = "VisitorCounter"
    }
  }

  # Ignore code changes during import
  lifecycle {
    ignore_changes = [
      filename,
      source_code_hash,
    ]
