# IAM: wildcard admin policy attached to a role any AWS principal can assume.
resource "aws_iam_role" "admin" {
  name = "tigergate-fixture-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "star" {
  name = "tigergate-fixture-star"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "star" {
  role       = aws_iam_role.admin.name
  policy_arn = aws_iam_policy.star.arn
}

resource "aws_iam_user" "ci" {
  name = "tigergate-ci"
}

resource "aws_iam_user_policy_attachment" "ci_admin" {
  user       = aws_iam_user.ci.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}

# Weak account password policy.
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 6
  require_lowercase_characters   = false
  require_numbers                = false
  require_uppercase_characters   = false
  require_symbols                = false
  allow_users_to_change_password = true
  max_password_age               = 0
  password_reuse_prevention      = 0
}
