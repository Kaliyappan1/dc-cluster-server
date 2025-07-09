terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Get next available key name
data "external" "key_check" {
  program = ["${path.module}/scripts/check_key.sh", var.key_name, var.aws_region]
}

locals {
  raw_key_name   = data.external.key_check.result.final_key_name
  final_key_name = replace(local.raw_key_name, " ", "-")
}

# Generate PEM key
resource "tls_private_key" "generated_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Create EC2 Key Pair
resource "aws_key_pair" "generated_key_pair" {
  key_name   = local.final_key_name
  public_key = tls_private_key.generated_key.public_key_openssh
}

# Upload PEM to S3
resource "aws_s3_object" "upload_pem_key" {
  bucket  = "splunk-deployment-prod"
  key     = "${var.usermail}/keys/${local.final_key_name}.pem"
  content = tls_private_key.generated_key.private_key_pem
}

# Save PEM file locally
resource "local_file" "pem_file" {
  filename        = "${path.module}/${local.final_key_name}.pem"
  content         = tls_private_key.generated_key.private_key_pem
  file_permission = "0400"
}

resource "random_id" "sg_suffix" {
  byte_length = 2
}

# Security Groups for each instance
data "aws_ami" "rhel9" {
  most_recent = true

  filter {
    name   = "name"
    values = ["RHEL-9.*x86_64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["309956199498"]
}

# Create Distributed Clustered EC2 Instances
resource "aws_instance" "splunk_cluster" {
  count                  = 9
  ami                    = data.aws_ami.rhel9.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.generated_key_pair.key_name
  vpc_security_group_ids = [aws_security_group.splunk_sg.id]

  root_block_device {
    volume_size = var.storage_size
  }

  tags = {
    Name          = replace(element(["${var.instance_name}-ClusterMaster", "${var.instance_name}-idx1", "${var.instance_name}-idx2", "${var.instance_name}-idx3", "${var.instance_name}-SH1", "${var.instance_name}-SH2", "${var.instance_name}-SH3", "${var.instance_name}-Management_server", "${var.instance_name}-IF"], count.index), " ", "-")
    AutoStop      = "true"
    Owner         = var.usermail
    UserEmail     = var.usermail
    RunQuotaHours = var.quotahours
    Category      = var.category
    PlanStartDate = var.planstartdate
  }
}

# Security Group
resource "aws_security_group" "splunk_sg" {
  name        = "splunk-security-group-${random_id.sg_suffix.hex}"
  description = "Security group for Splunk server"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8000
    to_port     = 9999
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "instance_public_ips" {
  value = {
    for idx, instance in aws_instance.splunk_cluster :
    instance.tags["Name"] => instance.public_ip
  }
}

output "final_key_name" {
  value = local.final_key_name
}

output "s3_key_path" {
  value = "${var.usermail}/keys/${local.final_key_name}.pem"
}
