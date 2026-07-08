output "vpc_id" {
  description = "VPC network ID"
  value       = module.networking.vpc_id
}

output "gke_cluster_name" {
  description = "GKE cluster name"
  value       = module.gke.cluster_name
}

output "gke_cluster_endpoint" {
  description = "GKE cluster API endpoint"
  value       = module.gke.cluster_endpoint
}

output "artifact_registry_url" {
  description = "Artifact Registry URL"
  value       = module.artifact_registry.registry_url
}

output "kubeconfig_command" {
  description = "Command to configure kubectl"
  value       = "gcloud container clusters get-credentials ${module.gke.cluster_name} --region ${var.region} --project ${var.gcp_project_id}"
}
