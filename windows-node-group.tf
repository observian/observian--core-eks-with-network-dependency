# resource "aws_eks_node_group" "windows_node_group" {
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
#   launch_template = {
#     name = aws_launch_template.eks_windows_node_group_launch_template
#   }

# }

# resource "aws_launch_template" "eks_windows_node_group_launch_template" {
#   name = "windows_eks_launch_template"
#   description = "windows template for launching windows instances into EKS"
#   block_device_mappings {
#     device_name = "/dev/sda1"

#     ebs {
#       delete_on_termination = true
#       volume_size = var.windows_node_volume_size
#       volume_type = "gp2"
#     }
#   }
#   iam_instance_profile {
#     name = "test"
#   }

#   image_id = var.windows_ami_id
#   key_name = var.windows_aws_key_name
#   security_group_names = [data.aws_security_group.eks-security-group.id]
#   user_data = filebase64("")

# }
