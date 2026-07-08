variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "cyber-agent"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "provider_type" {
  description = "Cloud provider: aws or gcp"
  type        = string
  validation {
    condition     = contains(["aws", "gcp"], var.provider_type)
    error_message = "provider_type must be 'aws' or 'gcp'"
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Cloud region"
  type        = string
}

# --- AWS VPC Resources ---

resource "aws_vpc" "main" {
  count = var.provider_type == "aws" ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-vpc"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_subnet" "public" {
  count = var.provider_type == "aws" ? length(var.availability_zones) : 0

  vpc_id                  = aws_vpc.main[0].id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                                           = "${var.project_name}-public-${var.availability_zones[count.index]}"
    "kubernetes.io/role/elb"                        = "1"
    "kubernetes.io/cluster/${var.project_name}-eks" = "shared"
  }
}

resource "aws_subnet" "private" {
  count = var.provider_type == "aws" ? length(var.availability_zones) : 0

  vpc_id            = aws_vpc.main[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + length(var.availability_zones))
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name                                           = "${var.project_name}-private-${var.availability_zones[count.index]}"
    "kubernetes.io/role/internal-elb"               = "1"
    "kubernetes.io/cluster/${var.project_name}-eks" = "shared"
  }
}

resource "aws_internet_gateway" "main" {
  count  = var.provider_type == "aws" ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  tags = {
    Name = "${var.project_name}-${var.environment}-igw"
  }
}

resource "aws_eip" "nat" {
  count  = var.provider_type == "aws" ? 1 : 0
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-${var.environment}-nat-eip"
  }
}

resource "aws_nat_gateway" "main" {
  count         = var.provider_type == "aws" ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.project_name}-${var.environment}-nat"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  count  = var.provider_type == "aws" ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table" "private" {
  count  = var.provider_type == "aws" ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[0].id
  }

  tags = {
    Name = "${var.project_name}-private-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = var.provider_type == "aws" ? length(var.availability_zones) : 0
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table_association" "private" {
  count          = var.provider_type == "aws" ? length(var.availability_zones) : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

# --- GCP VPC Resources ---

resource "google_compute_network" "main" {
  count                   = var.provider_type == "gcp" ? 1 : 0
  name                    = "${var.project_name}-${var.environment}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "nodes" {
  count         = var.provider_type == "gcp" ? 1 : 0
  name          = "${var.project_name}-${var.environment}-nodes"
  ip_cidr_range = "10.0.0.0/20"
  region        = var.region
  network       = google_compute_network.main[0].id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.4.0.0/14"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.8.0.0/20"
  }

  private_ip_google_access = true
}

resource "google_compute_router" "main" {
  count   = var.provider_type == "gcp" ? 1 : 0
  name    = "${var.project_name}-${var.environment}-router"
  region  = var.region
  network = google_compute_network.main[0].id
}

resource "google_compute_router_nat" "main" {
  count                              = var.provider_type == "gcp" ? 1 : 0
  name                               = "${var.project_name}-${var.environment}-nat"
  router                             = google_compute_router.main[0].name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# --- Outputs ---

output "vpc_id" {
  value = var.provider_type == "aws" ? aws_vpc.main[0].id : google_compute_network.main[0].id
}

output "public_subnet_ids" {
  value = var.provider_type == "aws" ? aws_subnet.public[*].id : []
}

output "private_subnet_ids" {
  value = var.provider_type == "aws" ? aws_subnet.private[*].id : [google_compute_subnetwork.nodes[0].id]
}
