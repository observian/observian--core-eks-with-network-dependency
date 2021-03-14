data "aws_eks_cluster" "base-cluster" {
  name = module.base-cluster.cluster_id
}

data "aws_eks_cluster_auth" "base-cluster" {
  name = module.base-cluster.cluster_id
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.base-cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.base-cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.base-cluster.token
  load_config_file       = false
  version                = "~> 1.9"
}

module "base-cluster" {
  source          = "terraform-aws-modules/eks/aws"
  cluster_name    = "base-cluster"
  cluster_version = "1.17"
  subnets         = [data.aws_subnet.base-app-public-alpha.id
                    , data.aws_subnet.base-app-public-bravo.id
                    , data.aws_subnet.base-app-private-alpha.id
                    , data.aws_subnet.base-app-private-bravo.id]
  vpc_id          = data.aws_vpc.base-app-vpc.id

  worker_groups = [
    {
      name                = "on-demand-1"
      instance_type       = "m4.xlarge"
      asg_max_size        = 1
      kubelet_extra_args  = "--node-labels=node.kubernetes.io/lifecycle=normal"
      suspended_processes = ["AZRebalance"]
    },
    {
      name                = "spot-1"
      spot_price          = "0.199"
      instance_type       = "c4.xlarge"
      asg_max_size        = 20
      kubelet_extra_args  = "--node-labels=node.kubernetes.io/lifecycle=spot"
      suspended_processes = ["AZRebalance"]
    },
    {
      name                = "spot-2"
      spot_price          = "0.20"
      instance_type       = "m4.xlarge"
      asg_max_size        = 20
      kubelet_extra_args  = "--node-labels=node.kubernetes.io/lifecycle=spot"
      suspended_processes = ["AZRebalance"]
    }
  ]
}

# resource "aws_eks_cluster" "base-cluster" {
#   name     = var.eks_cluster_name
#   role_arn = aws_iam_role.eks-role.arn
#   vpc_config {
#     subnet_ids = [data.aws_subnet.base-app-public-alpha.id
#       , data.aws_subnet.base-app-public-bravo.id
#       , data.aws_subnet.base-app-private-alpha.id
#     , data.aws_subnet.base-app-private-bravo.id]
#     endpoint_private_access = true
#     endpoint_public_access  = true
#     security_group_ids      = [data.aws_security_group.eks-security-group.id]
#   }

#   enabled_cluster_log_types = ["api", "audit", "controllerManager", "scheduler"]

#   depends_on = [aws_iam_role_policy_attachment.test-AmazonEKSClusterPolicy]
# }

# data "aws_security_group" "eks-security-group" {
#     filter {
#         name = "tag:Name"
#         values = ["terraform-eks-demo"]
#     }
# }

# resource "aws_eks_node_group" "eks-node-group" {
#   cluster_name    = var.eks_cluster_name
#   node_group_name = "eks-node-group"
#   node_role_arn   = aws_iam_role.eks-node-group-role.arn
#   subnet_ids = [
#     data.aws_subnet.base-app-private-bravo.id
#     , data.aws_subnet.base-app-private-alpha.id
#   ]

#   scaling_config {
#     desired_size = 1
#     max_size     = 10
#     min_size     = 1
#   }
#   tags = {
#     "kubernetes.io/cluster/${var.eks_cluster_name}"     = "owned",
#     "k8s.io/cluster-autoscaler/${var.eks_cluster_name}" = "owned",
#     "k8s.io/cluster-autoscaler/enabled"                 = "true"

#   }

#   # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
#   # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
#   depends_on = [
#     aws_iam_role_policy_attachment.example-AmazonEKSWorkerNodePolicy
#     , aws_iam_role_policy_attachment.example-AmazonEKS_CNI_Policy
#     , aws_iam_role_policy_attachment.example-AmazonEC2ContainerRegistryReadOnly
#     , aws_eks_cluster.base-cluster
#   ]
# }