# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# SGEA sandbox network fixture — NOT part of the enclave.
#
# The enclave deliberately does not create its VPC (the customer's network team owns it).
# For a single-account sandbox test this creates a private, internet-less VPC shaped the
# way the enclave expects, and prints the enclave input variables:
#
#   terraform apply
#   terraform output -json enclave_inputs > ../../build/<profile-id>/terraform/network.auto.tfvars.json
#
# No NAT / internet gateway: every AWS API is reached through the enclave's VPC endpoints.
terraform {
  required_version = ">= 1.11"
  backend "local" {} # path set at init: -backend-config=path=...
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.29" }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}
variable "name" {
  type    = string
  default = "sgea-sandbox"
}
variable "cidr" {
  type    = string
  default = "10.42.0.0/16"
}

provider "aws" {
  region = var.region
  default_tags { tags = { "sgea:fixture" = "sandbox-network" } }
}

data "aws_availability_zones" "this" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.this.names, 0, 2)
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.7.3"

  name                          = var.name
  cidr                          = var.cidr
  azs                           = local.azs
  private_subnets               = [for i, _ in local.azs : cidrsubnet(var.cidr, 8, i)]       # agents, endpoints, Aurora
  intra_subnets                 = [for i, _ in local.azs : cidrsubnet(var.cidr, 8, 100 + i)] # SCCA firewall (IL4/IL5)
  private_subnet_names          = [for az in local.azs : "${var.name}-private-${az}"]
  intra_subnet_names            = [for az in local.azs : "${var.name}-firewall-${az}"]
  enable_nat_gateway            = false
  create_igw                    = false
  enable_dns_hostnames          = true # required for interface-endpoint private DNS
  enable_dns_support            = true
  manage_default_security_group = true # default SG with no rules
}

module "endpoints_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "6.0.0"

  name        = "${var.name}-endpoints"
  description = "HTTPS from inside the enclave VPC to interface endpoints"
  vpc_id      = module.vpc.vpc_id
  ingress_rules = {
    https = { cidr_ipv4 = var.cidr, from_port = 443, to_port = 443, description = "HTTPS from the enclave VPC" }
  }
}

# S3 is reached through the gateway endpoint at S3's public ranges: security groups must allow the
# S3 managed prefix list (ECR image layers come from S3 — without this the runtime cannot pull).
data "aws_ec2_managed_prefix_list" "s3" {
  name = "com.amazonaws.${var.region}.s3"
}

# Same for the DynamoDB gateway endpoint (token-control ledger: meter + gateway interceptor).
data "aws_ec2_managed_prefix_list" "dynamodb" {
  name = "com.amazonaws.${var.region}.dynamodb"
}

module "agents_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "6.0.0"

  name        = "${var.name}-agents"
  description = "Agent runtimes / tool Lambdas: egress to enclave endpoints only"
  vpc_id      = module.vpc.vpc_id
  egress_rules = {
    https    = { cidr_ipv4 = var.cidr, from_port = 443, to_port = 443, description = "Enclave VPC endpoints" }
    postgres = { cidr_ipv4 = var.cidr, from_port = 5432, to_port = 5432, description = "Aurora vector store" }
    s3       = { prefix_list_id = data.aws_ec2_managed_prefix_list.s3.id, from_port = 443, to_port = 443, description = "S3 gateway endpoint (ECR layers)" }
    dynamodb = { prefix_list_id = data.aws_ec2_managed_prefix_list.dynamodb.id, from_port = 443, to_port = 443, description = "DynamoDB gateway endpoint (token ledger)" }
  }
}

module "aurora_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "6.0.0"

  name        = "${var.name}-aurora"
  description = "Aurora PostgreSQL from agent runtimes only"
  vpc_id      = module.vpc.vpc_id
  ingress_rules = {
    postgres = { referenced_security_group_id = module.agents_sg.id, from_port = 5432, to_port = 5432, description = "From agent runtimes" }
  }
}

output "enclave_inputs" {
  description = "Enclave root variables (write to build/<profile-id>/terraform/network.auto.tfvars.json)."
  value = {
    vpc_id                      = module.vpc.vpc_id
    endpoint_subnet_ids         = module.vpc.private_subnets
    endpoint_security_group_ids = [module.endpoints_sg.id]
    endpoint_route_table_ids    = module.vpc.private_route_table_ids
    aurora_subnet_ids           = module.vpc.private_subnets
    aurora_security_group_ids   = [module.aurora_sg.id]
    agent_subnet_ids            = module.vpc.private_subnets
    agent_security_group_ids    = [module.agents_sg.id]
    scca_firewall_subnet_ids    = module.vpc.intra_subnets
  }
}
