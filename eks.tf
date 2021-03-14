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
  subnets = [data.aws_subnet.base-app-public-alpha.id
    , data.aws_subnet.base-app-public-bravo.id
    , data.aws_subnet.base-app-private-alpha.id
  , data.aws_subnet.base-app-private-bravo.id]
  vpc_id = data.aws_vpc.base-app-vpc.id


  worker_groups = [
    {
      name                = "on-demand-1"
      instance_type       = "m4.xlarge"
      asg_max_size        = 1
      kubelet_extra_args  = "--node-labels=node.kubernetes.io/lifecycle=normal"
      suspended_processes = ["AZRebalance"]
      root_volume_type    = "gp2",
      image_id = "ami-0fc3ca5b2c5e1fb11"
    },
    {
      name                = "spot-1"
      spot_price          = "0.199"
      instance_type       = "c4.xlarge"
      asg_max_size        = 20
      kubelet_extra_args  = "--node-labels=node.kubernetes.io/lifecycle=spot"
      suspended_processes = ["AZRebalance"]
      root_volume_type    = "gp2",
      image_id = "ami-0fc3ca5b2c5e1fb11"
      
    },
    {
      name                = "spot-2"
      spot_price          = "0.20"
      instance_type       = "m4.xlarge"
      asg_max_size        = 20
      kubelet_extra_args  = "--node-labels=node.kubernetes.io/lifecycle=spot"
      suspended_processes = ["AZRebalance"]
      root_volume_type    = "gp2",
      image_id = "ami-0fc3ca5b2c5e1fb11"
    }
  ]
}
