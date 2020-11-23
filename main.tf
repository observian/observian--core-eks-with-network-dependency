provider "aws" {
  version             = "~>2.0"
  region              = var.aws_region
  allowed_account_ids = var.allowed_account_ids
}

terraform {
  backend "remote" {
    hostname = "app.terraform.io"
    organization = "Observian"

    workspaces {
      prefix = "observian--core-eks-"
    }
  }
}

