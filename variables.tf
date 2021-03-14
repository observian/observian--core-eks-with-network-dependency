variable "eks_cluster_name" {
}

variable "application" {
}

variable "env" {
}

variable "aws_region" {
    
}

# variable "windows_node_volume_size" {
#   description = "EBS volume size for windows EKS nodes"
#   default = 50
# }

# variable "windows_aws_key_name" {
#   description = "the key to use for SSH purposes on the windows box -- probably will never use this, but it's required for the resource block"
#   default = aws_key_pair.windows_ssh_key.name
# }

# variable "public_key" {
#   description = "default public key to use to ssh into the box.  I can give you the private key if you end up using this"
#   default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCw3ES46BpllxGOoV6qEhYvz1mCo3ukKY32WeH+3R00VY0WQd8WzvqW+2XNDTwErS31TanulimJErVeOsAeTV27VbuSzFVPE+EccD7mddt0SuaYoJ+ShiveyKtcqdC/McXNCcCnZVofZj9So4j231oiWQrtDLQjFAP8uRPCc26ySZXQBU0gmngPYCwINkTaRv7+eleaVHsy1V+P+VfHpdLj777lDmuDRSCwhT+E6CVWzsRvhDtEFDTIID54oNow1K1MAyvUFoXOJCbLH1yF9pIGNRbWNYB3UU1P4nv0zY2rGz2UX0LTCyU3B5dvNI7vXDQGjKZEx71RH3zoTCvG7ZrJxjbwvb1HGVaU5BoWEyco3+EfQpVE9dFff1pMq4s6l7Nthp50JrJcAO2g8kcfCX34oIEnqaFt429dqs4VCvZ3Qn6w58R9w0e3rdGTDBY38eUEc2HwnlMp/GxJB2YKZkCXmVQk7SYaKaE340uYuc8S2yftN7XCQICVMQMiBZHvy0TDOZFE4cXEg6nx5W/GHTI0Y2k5ji0Wst4R0kVprYdAsMasEupoNake93WN3uoqDgaAMrT0WqHSNDQOQXl7hXKqK2MJt07tbbxMYg/SLGA0sVGsntSpRnf8k+DLEkdU2qyjBGxYDOvyNMUtr5G8ZgH/zbSdfoV3W8u6wOxsoWTr3w== dan.taylor@observian.com"
# }

# variable "windows_ami_id" {
#   description = "the ami to use for windows EKS node"
#   default = data.aws_ssm_parameter.windows_ami.value
# }

variable "namespace" {
  description = "default namespace that isn't the default namespace.  Defaults to \"development\""
  default     = "development"
}

variable "k8s-user-names" {
  description = "users who should have read-access to the cluster"
  default = [
    "user1",
    "user2",
    "user3"
  ]

}

variable "allowed_account_ids" {
}

variable "public_key" {
  
}