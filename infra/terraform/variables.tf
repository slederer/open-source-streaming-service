variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used as prefix for resource naming"
  type        = string
  default     = "oss-streaming"
}

variable "ec2_instance_type" {
  description = "EC2 instance type for the application server"
  type        = string
  default     = "t3.medium"
}

variable "ec2_key_pair_name" {
  description = "Name of an existing EC2 key pair for SSH access"
  type        = string
}

variable "ec2_ami_id" {
  description = "AMI ID for EC2 instance (Amazon Linux 2023). Leave empty to auto-detect latest."
  type        = string
  default     = ""
}

variable "ad_decision_server_url" {
  description = "VAST/VMAP endpoint URL for MediaTailor ad decision server"
  type        = string
  default     = "https://pubads.g.doubleclick.net/gampad/ads?iu=/21775744923/external/single_ad_samples&sz=640x480&cust_params=sample_ct%3Dlinear&ciu_szs=300x250%2C728x90&gdfp_req=1&output=vast&unviewed_position_start=1&env=vp&impl=s&correlator="
}

variable "domain_name" {
  description = "Optional custom domain name for CloudFront (leave empty to use default CloudFront domain)"
  type        = string
  default     = ""
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH into the EC2 instance"
  type        = string
  default     = "0.0.0.0/0"
}
