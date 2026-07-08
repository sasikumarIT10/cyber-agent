variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "cyber-agent"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "gke_cluster_version" {
  description = "GKE Kubernetes version"
  type        = string
  default     = "1.29"
}

variable "machine_type" {
  description = "GCE machine type for nodes"
  type        = string
  default     = "e2-medium"
}

variable "node_count" {
  description = "Initial node count"
  type        = number
  default     = 2
}

variable "min_node_count" {
  description = "Minimum nodes in autoscaling"
  type        = number
  default     = 1
}

variable "max_node_count" {
  description = "Maximum nodes in autoscaling"
  type        = number
  default     = 5
}

variable "alert_email" {
  description = "Email for monitoring alerts"
  type        = string
  default     = ""
}
