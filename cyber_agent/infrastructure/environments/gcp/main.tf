terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.region
}

# --- Networking ---

module "networking" {
  source = "../../modules/networking"

  project_name  = var.project_name
  environment   = var.environment
  provider_type = "gcp"
  region        = var.region
}

# --- GKE Cluster ---

module "gke" {
  source = "../../modules/gke-cluster"

  project_name    = var.project_name
  environment     = var.environment
  gcp_project_id  = var.gcp_project_id
  region          = var.region
  network_id      = module.networking.vpc_id
  subnetwork_id   = module.networking.private_subnet_ids[0]
  cluster_version = var.gke_cluster_version
  machine_type    = var.machine_type
  node_count      = var.node_count
  min_node_count  = var.min_node_count
  max_node_count  = var.max_node_count
}

# --- Container Registry ---

module "artifact_registry" {
  source = "../../modules/container-registry"

  project_name   = var.project_name
  environment    = var.environment
  provider_type  = "gcp"
  region         = var.region
  gcp_project_id = var.gcp_project_id
}

# --- Monitoring ---

module "monitoring" {
  source = "../../modules/monitoring"

  project_name   = var.project_name
  environment    = var.environment
  provider_type  = "gcp"
  cluster_name   = module.gke.cluster_name
  gcp_project_id = var.gcp_project_id
  alert_email    = var.alert_email
}
