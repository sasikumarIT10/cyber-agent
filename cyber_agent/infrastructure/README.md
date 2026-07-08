# Infrastructure as Code

Terraform modules for deploying the Cybersecurity AI Agent on AWS (EKS) and GCP (GKE).

## Architecture

```
                    ┌──────────────────────────────┐
                    │     GitHub Actions CI/CD      │
                    │  test → build → tf → helm    │
                    └──────────┬───────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                                 │
    ┌─────────▼─────────┐           ┌──────────▼─────────┐
    │       AWS         │           │        GCP         │
    │                   │           │                    │
    │  VPC (3 AZ)       │           │  VPC + Subnets     │
    │  ├─ Public subs   │           │  ├─ Pod range      │
    │  ├─ Private subs  │           │  └─ Service range  │
    │  ├─ NAT Gateway   │           │  Cloud NAT         │
    │  └─ IGW           │           │                    │
    │                   │           │                    │
    │  EKS Cluster      │           │  GKE Cluster       │
    │  ├─ Managed nodes │           │  ├─ Node pool      │
    │  ├─ IRSA (OIDC)   │           │  ├─ Workload ID    │
    │  ├─ KMS encrypt   │           │  ├─ Binary Auth    │
    │  └─ ALB Ingress   │           │  └─ Cloud Armor    │
    │                   │           │                    │
    │  ECR (immutable)  │           │  Artifact Registry │
    │  CloudWatch       │           │  Cloud Monitoring  │
    │  SNS Alerts       │           │  Alert Policies    │
    └───────────────────┘           └────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| `modules/networking` | VPC, subnets, NAT, routing (AWS & GCP) |
| `modules/eks-cluster` | EKS cluster, node groups, IAM, KMS, OIDC |
| `modules/gke-cluster` | GKE cluster, node pools, Workload Identity, Cloud Armor |
| `modules/container-registry` | ECR (AWS) and Artifact Registry (GCP) with lifecycle policies |
| `modules/monitoring` | CloudWatch/Cloud Monitoring alerts for CPU and memory |

## Usage

### AWS

```bash
cd environments/aws
cp terraform.tfvars.example terraform.tfvars
# Edit with your values
terraform init
terraform plan
terraform apply
```

### GCP

```bash
cd environments/gcp
cp terraform.tfvars.example terraform.tfvars
# Edit with your values
terraform init
terraform plan
terraform apply
```

## State Management

- **AWS**: S3 bucket + DynamoDB table for state locking
- **GCP**: GCS bucket for state storage

Create state backends before first run:

```bash
# AWS
aws s3 mb s3://cyber-agent-terraform-state
aws dynamodb create-table \
  --table-name cyber-agent-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# GCP
gsutil mb gs://cyber-agent-terraform-state
```

## Security Features

- Private EKS/GKE endpoints with controlled public access
- KMS encryption for Kubernetes secrets (EKS)
- Binary Authorization (GKE)
- Cloud Armor WAF rules (XSS, SQLi protection)
- Network policies via Calico
- Immutable container image tags
- Automatic image scanning on push (ECR)
- NAT gateway for private subnet egress
- IRSA/Workload Identity (no static credentials in pods)
