terraform {
  backend "gcs" {
    bucket = "cyber-agent-terraform-state"
    prefix = "gcp/prod/terraform"
  }
}
