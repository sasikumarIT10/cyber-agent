terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# --- Networking ---

module "networking" {
  source = "../../modules/networking"

  project_name       = var.project_name
  environment        = var.environment
  provider_type      = "aws"
  region             = var.region
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
}

# --- EKS Cluster ---

module "eks" {
  source = "../../modules/eks-cluster"

  project_name        = var.project_name
  environment         = var.environment
  cluster_version     = var.eks_cluster_version
  vpc_id              = module.networking.vpc_id
  private_subnet_ids  = module.networking.private_subnet_ids
  public_subnet_ids   = module.networking.public_subnet_ids
  node_instance_types = var.node_instance_types
  node_desired_size   = var.node_desired_size
  node_min_size       = var.node_min_size
  node_max_size       = var.node_max_size
}

# --- Container Registry ---

module "ecr" {
  source = "../../modules/container-registry"

  project_name   = var.project_name
  environment    = var.environment
  provider_type  = "aws"
  region         = var.region
}

# --- Monitoring ---

module "monitoring" {
  source = "../../modules/monitoring"

  project_name  = var.project_name
  environment   = var.environment
  provider_type = "aws"
  cluster_name  = module.eks.cluster_name
  alert_email   = var.alert_email
}
