# CWE-798: static provider credentials committed to source.
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAQ4FIXTURE0TEST01"
  secret_key = "fx7Q9tZ2mK4pL8wR1nB5vC3yH6jD0sA2eG9uT4iX"
}

terraform {
  backend "s3" {
    bucket  = "tigergate-test-cpp-tfstate"
    key     = "state.tfstate"
    region  = "us-east-1"
    encrypt = false
  }
}
