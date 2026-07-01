# Sample Terraform configuration for PQC scanner demo
# This file contains various crypto configurations to demonstrate scanning

provider "aws" {
  region = "us-east-1"
}

# KMS Key using RSA - quantum vulnerable
resource "aws_kms_key" "signing_key" {
  description             = "RSA signing key for document verification"
  customer_master_key_spec = "RSA_2048"
  key_usage               = "SIGN_VERIFY"

  tags = {
    Environment = "production"
    Purpose     = "document-signing"
  }
}

# KMS Key using ECC - quantum vulnerable
resource "aws_kms_key" "ecc_key" {
  description             = "ECDSA key for API authentication"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage               = "SIGN_VERIFY"

  tags = {
    Environment = "production"
    Purpose     = "api-auth"
  }
}

# S3 bucket with AES-256 encryption - quantum safe
resource "aws_s3_bucket_server_side_encryption_configuration" "data_bucket" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      # Uses AES-256 under the hood
    }
  }
}

# TLS private key - quantum vulnerable
resource "tls_private_key" "service_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

# ACM certificate
resource "aws_acm_certificate" "api_cert" {
  domain_name       = "api.example.com"
  validation_method = "DNS"

  # Uses RSA by default
  key_algorithm = "RSA_2048"

  lifecycle {
    create_before_destroy = true
  }
}

# RDS with encryption
resource "aws_db_instance" "primary" {
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  storage_encrypted    = true
  # Default KMS key uses AES-256
  
  allocated_storage = 100
}
