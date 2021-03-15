resource "aws_eks_cluster" "base-cluster" {
  name     = var.eks_cluster_name
  role_arn = aws_iam_role.eks-role.arn
  vpc_config {
    subnet_ids = [data.aws_subnet.base-app-public-alpha.id
      , data.aws_subnet.base-app-public-bravo.id
      , data.aws_subnet.base-app-private-alpha.id
    , data.aws_subnet.base-app-private-bravo.id]
    endpoint_private_access = true
    endpoint_public_access  = true
    security_group_ids      = [data.aws_security_group.eks-security-group.id]
  }

  enabled_cluster_log_types = ["api", "audit", "controllerManager", "scheduler"]

  depends_on = [aws_iam_role_policy_attachment.test-AmazonEKSClusterPolicy]
}

data "aws_security_group" "eks-security-group" {
    filter {
        name = "tag:Name"
        values = ["terraform-eks-demo"]
    }
}

resource "aws_eks_node_group" "eks-node-group" {
  cluster_name    = var.eks_cluster_name
  node_group_name = "eks-node-group"
  node_role_arn   = aws_iam_role.eks-node-group-role.arn
  subnet_ids = [
    data.aws_subnet.base-app-private-bravo.id
    , data.aws_subnet.base-app-private-alpha.id
  ]

  scaling_config {
    desired_size = 1
    max_size     = 10
    min_size     = 1
  }
  tags = {
    "kubernetes.io/cluster/${var.eks_cluster_name}"     = "owned",
    "k8s.io/cluster-autoscaler/${var.eks_cluster_name}" = "owned",
    "k8s.io/cluster-autoscaler/enabled"                 = "true"

  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSWorkerNodePolicy
    , aws_iam_role_policy_attachment.example-AmazonEKS_CNI_Policy
    , aws_iam_role_policy_attachment.example-AmazonEC2ContainerRegistryReadOnly
    , aws_eks_cluster.base-cluster
  ]
}

resource "aws_eks_node_group" "spot-eks-node-group" {
  cluster_name    = var.eks_cluster_name
  capacity_type = "SPOT"
  node_group_name = "spot-eks-node-group"
  node_role_arn   = aws_iam_role.eks-node-group-role.arn
  subnet_ids = [
    data.aws_subnet.base-app-private-bravo.id
    , data.aws_subnet.base-app-private-alpha.id
  ]

  scaling_config {
    desired_size = 1
    max_size     = 10
    min_size     = 1
  }
  tags = {
    "kubernetes.io/cluster/${var.eks_cluster_name}"     = "owned",
    "k8s.io/cluster-autoscaler/${var.eks_cluster_name}" = "owned",
    "k8s.io/cluster-autoscaler/enabled"                 = "true"

  }
  instance_types =  [
    "m4.large",
    "m5.large",
    "m5a.large",
    "m5n.large"
  ]
  labels = {
    "lifecycle" = "spot"
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSWorkerNodePolicy
    , aws_iam_role_policy_attachment.example-AmazonEKS_CNI_Policy
    , aws_iam_role_policy_attachment.example-AmazonEC2ContainerRegistryReadOnly
    , aws_eks_cluster.base-cluster
  ]
}