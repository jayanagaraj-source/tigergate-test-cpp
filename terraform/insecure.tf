# Deliberately insecure IaC fixture for scanner validation. Do not apply.

# S3: public, unversioned, unencrypted, no logging.
resource "aws_s3_bucket" "public_fixture" {
  bucket = "tigergate-test-cpp-public-fixture"
  acl    = "public-read-write"
  tags   = { Environment = "fixture" }
}

resource "aws_s3_bucket_public_access_block" "public_fixture" {
  bucket                  = aws_s3_bucket.public_fixture.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_fixture" {
  bucket = aws_s3_bucket.public_fixture.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
      Resource  = "${aws_s3_bucket.public_fixture.arn}/*"
    }]
  })
}

# EC2: public IP, IMDSv1, unencrypted root volume, user-data with secrets.
resource "aws_instance" "build_agent" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.medium"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.wide_open.id]
  monitoring                  = false
  ebs_optimized               = false

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  root_block_device {
    encrypted = false
  }

  user_data = <<-USERDATA
    #!/bin/bash
    export AWS_ACCESS_KEY_ID=AKIAQ4FIXTURE0TEST01
    export AWS_SECRET_ACCESS_KEY=fx7Q9tZ2mK4pL8wR1nB5vC3yH6jD0sA2eG9uT4iX
    export DATABASE_URL=postgres://admin:password123@db.internal.example.com:5432/tigergate
    curl -sk http://install.example.com/agent.sh | bash
  USERDATA
}

# EBS: unencrypted volume.
resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# CloudTrail: single-region, no log validation, no encryption.
resource "aws_cloudtrail" "fixture" {
  name                          = "fixture-trail"
  s3_bucket_name                = aws_s3_bucket.public_fixture.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
}
