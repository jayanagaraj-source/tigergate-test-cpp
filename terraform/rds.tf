# RDS: public, unencrypted, hard-coded master password, no backups, no deletion protection.
resource "aws_db_instance" "fixture" {
  identifier                          = "tigergate-fixture"
  engine                              = "postgres"
  engine_version                      = "11.5"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "admin"
  password                            = "password123"
  publicly_accessible                 = true
  storage_encrypted                   = false
  backup_retention_period             = 0
  deletion_protection                 = false
  skip_final_snapshot                 = true
  iam_database_authentication_enabled = false
  auto_minor_version_upgrade          = false
  multi_az                            = false
  vpc_security_group_ids              = [aws_security_group.wide_open.id]
}

# Secrets Manager entry whose value is inline in the plan.
resource "aws_secretsmanager_secret" "db" {
  name = "tigergate/fixture/db"
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({ username = "admin", password = "password123" })
}

# Lambda with secrets in plain environment variables and no tracing.
resource "aws_lambda_function" "webhook" {
  function_name = "tigergate-webhook"
  role          = aws_iam_role.admin.arn
  handler       = "index.handler"
  runtime       = "nodejs12.x"
  filename      = "webhook.zip"

  environment {
    variables = {
      GITHUB_TOKEN = "ghp_Fixture0TokenNotReal1234567890abcdEFGH"
      DATABASE_URL = "postgres://admin:password123@db.internal.example.com:5432/tigergate"
    }
  }
}
