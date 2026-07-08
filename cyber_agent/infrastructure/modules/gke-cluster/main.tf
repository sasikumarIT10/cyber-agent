variable "project_name" {
  type    = string
  default = "cyber-agent"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "network_id" {
  description = "VPC network self_link"
  type        = string
}

variable "subnetwork_id" {
  description = "Subnetwork self_link"
  type        = string
}

variable "cluster_version" {
  description = "GKE master version"
  type        = string
  default     = "1.29"
}

variable "machine_type" {
  type    = string
  default = "e2-medium"
}

variable "node_count" {
  type    = number
  default = 2
}

variable "min_node_count" {
  type    = number
  default = 1
}

variable "max_node_count" {
  type    = number
  default = 5
}

# --- GKE Cluster ---

resource "google_container_cluster" "main" {
  name     = "${var.project_name}-${var.environment}"
  location = var.region
  project  = var.gcp_project_id

  network    = var.network_id
  subnetwork = var.subnetwork_id

  # Use separately managed node pool
  remove_default_node_pool = true
  initial_node_count       = 1

  min_master_version = var.cluster_version

  # Workload Identity
  workload_identity_config {
    workload_pool = "${var.gcp_project_id}.svc.id.goog"
  }

  # Network policy
  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  # Private cluster
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  # IP allocation for pods and services
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  # Binary Authorization
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  # Master authorized networks
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "All (restrict in production)"
    }
  }

  # Logging and monitoring
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
    managed_prometheus {
      enabled = true
    }
  }

  # Security posture
  addons_config {
    network_policy_config {
      disabled = false
    }
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
  }

  resource_labels = {
    environment = var.environment
    managed-by  = "terraform"
    app         = var.project_name
  }
}

# --- Node Pool ---

resource "google_container_node_pool" "primary" {
  name       = "${var.project_name}-${var.environment}-pool"
  location   = var.region
  cluster    = google_container_cluster.main.name
  project    = var.gcp_project_id
  node_count = var.node_count

  autoscaling {
    min_node_count = var.min_node_count
    max_node_count = var.max_node_count
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type = var.machine_type
    disk_size_gb = 50
    disk_type    = "pd-standard"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    labels = {
      environment = var.environment
      app         = var.project_name
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }
}

# --- Cloud Armor security policy ---

resource "google_compute_security_policy" "main" {
  name    = "${var.project_name}-${var.environment}-policy"
  project = var.gcp_project_id

  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow rule"
  }

  rule {
    action   = "deny(403)"
    priority = "1000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-stable')"
      }
    }
    description = "Block XSS attacks"
  }

  rule {
    action   = "deny(403)"
    priority = "1001"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-stable')"
      }
    }
    description = "Block SQL injection"
  }
}

# --- Outputs ---

output "cluster_name" {
  value = google_container_cluster.main.name
}

output "cluster_endpoint" {
  value = google_container_cluster.main.endpoint
}

output "cluster_ca_certificate" {
  value = google_container_cluster.main.master_auth[0].cluster_ca_certificate
}

output "workload_identity_pool" {
  value = "${var.gcp_project_id}.svc.id.goog"
}
