variable "project_name" {
  type    = string
  default = "cyber-agent"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "provider_type" {
  description = "Cloud provider: aws or gcp"
  type        = string
}

variable "cluster_name" {
  type = string
}

variable "gcp_project_id" {
  type    = string
  default = ""
}

variable "alert_email" {
  description = "Email address for alert notifications"
  type        = string
  default     = ""
}

# --- AWS CloudWatch ---

resource "aws_cloudwatch_log_group" "eks" {
  count             = var.provider_type == "aws" ? 1 : 0
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    Application = var.project_name
  }
}

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  count               = var.provider_type == "aws" ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EKS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "CPU utilization exceeded 80% for 15 minutes"

  dimensions = {
    ClusterName = var.cluster_name
  }

  alarm_actions = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
}

resource "aws_cloudwatch_metric_alarm" "memory_high" {
  count               = var.provider_type == "aws" ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/EKS"
  period              = 300
  statistic           = "Average"
  threshold           = 85
  alarm_description   = "Memory utilization exceeded 85% for 15 minutes"

  dimensions = {
    ClusterName = var.cluster_name
  }

  alarm_actions = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
}

resource "aws_sns_topic" "alerts" {
  count = var.provider_type == "aws" && var.alert_email != "" ? 1 : 0
  name  = "${var.project_name}-${var.environment}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.provider_type == "aws" && var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- GCP Cloud Monitoring ---

resource "google_monitoring_alert_policy" "cpu_high" {
  count        = var.provider_type == "gcp" ? 1 : 0
  display_name = "${var.project_name} CPU High"
  project      = var.gcp_project_id
  combiner     = "OR"

  conditions {
    display_name = "CPU utilization > 80%"
    condition_threshold {
      filter          = "resource.type = \"k8s_container\" AND resource.labels.cluster_name = \"${var.cluster_name}\" AND metric.type = \"kubernetes.io/container/cpu/limit_utilization\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = var.alert_email != "" ? [google_monitoring_notification_channel.email[0].id] : []
}

resource "google_monitoring_alert_policy" "memory_high" {
  count        = var.provider_type == "gcp" ? 1 : 0
  display_name = "${var.project_name} Memory High"
  project      = var.gcp_project_id
  combiner     = "OR"

  conditions {
    display_name = "Memory utilization > 85%"
    condition_threshold {
      filter          = "resource.type = \"k8s_container\" AND resource.labels.cluster_name = \"${var.cluster_name}\" AND metric.type = \"kubernetes.io/container/memory/limit_utilization\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.85
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = var.alert_email != "" ? [google_monitoring_notification_channel.email[0].id] : []
}

resource "google_monitoring_notification_channel" "email" {
  count        = var.provider_type == "gcp" && var.alert_email != "" ? 1 : 0
  display_name = "${var.project_name} Alert Email"
  type         = "email"
  project      = var.gcp_project_id

  labels = {
    email_address = var.alert_email
  }
}

# --- Outputs ---

output "log_group_name" {
  value = var.provider_type == "aws" ? (length(aws_cloudwatch_log_group.eks) > 0 ? aws_cloudwatch_log_group.eks[0].name : "") : ""
}
