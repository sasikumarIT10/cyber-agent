terraform {
  backend "s3" {
    bucket         = "cyber-agent-terraform-state"
    key            = "aws/prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "cyber-agent-terraform-locks"
    encrypt        = true
  }
}
