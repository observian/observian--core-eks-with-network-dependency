resource "aws_iam_policy" "alb-ingress-controller-iam-policy" {
  name        = "tf-managed-ALBIngressControllerIAMPolicy"
  path        = "/"
  description = "Ingress controller policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "acm:DescribeCertificate",
          "acm:ListCertificates",
          "acm:GetCertificate"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateSecurityGroup",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeTags",
          "ec2:DescribeVpcs",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:RevokeSecurityGroupIngress"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "elasticloadbalancing:AddListenerCertificates",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateRule",
          "elasticloadbalancing:CreateTargetGroup",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:DeleteRule",
          "elasticloadbalancing:DeleteTargetGroup",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeTags",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:ModifyRule",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:RemoveListenerCertificates",
          "elasticloadbalancing:RemoveTags",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:SetWebACL"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "iam:CreateServiceLinkedRole",
          "iam:GetServerCertificate",
          "iam:ListServerCertificates"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "cognito-idp:DescribeUserPoolClient"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "waf-regional:GetWebACLForResource",
          "waf-regional:GetWebACL",
          "waf-regional:AssociateWebACL",
          "waf-regional:DisassociateWebACL"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "tag:GetResources",
          "tag:TagResources"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "waf:GetWebACL"
        ],
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_role" "alb-ingress-controller-service-account" {
  name = "tf-managed-alb-ingress-controller-service-account"
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      },
      {
        "Sid" : "",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : aws_iam_role.eks-node-group-role.arn
        },
        "Action" : "sts:AssumeRole"
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks-role.name
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks-node-group-role.name
}

resource "aws_iam_role_policy_attachment" "example-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks-node-group-role.name
}

resource "aws_iam_role_policy_attachment" "alb-service-account-attachment" {
  policy_arn = aws_iam_policy.alb-ingress-controller-iam-policy.arn
  role       = aws_iam_role.alb-ingress-controller-service-account.name
}

resource "aws_iam_role" "eks-role" {
  name = "tf-managed-eks-role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}



resource "aws_iam_role" "eks-node-group-role" {
  name = "tf-managed-eks-node-group-role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "test-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks-role.name
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.eks-role.name
}

resource "aws_iam_role_policy_attachment" "test-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks-node-group-role.name
}

resource "aws_iam_role_policy_attachment" "ecr-policy-attachment" {
  policy_arn = aws_iam_policy.ecr-policy.arn
  role       = aws_iam_role.eks-node-group-role.name
}
resource "aws_iam_role_policy_attachment" "assume-role-policy-attachment" {
  policy_arn = aws_iam_policy.eks-assume-role-policy.arn
  role       = aws_iam_role.eks-node-group-role.name
}

resource "aws_iam_role_policy_attachment" "eks-autoscaling-attachment" {
  policy_arn = aws_iam_policy.eks-autoscaling-policy.arn
  role       = aws_iam_role.eks-node-group-role.name
}

resource "aws_iam_role_policy_attachment" "ssm-reader-for-pods-attachment" {
  policy_arn = aws_iam_policy.ssm-policy.arn
  role       = aws_iam_role.ssm-reader.name
}

resource "aws_iam_policy" "ecr-policy" {
  name        = "tf-managed-ecr-policy"
  path        = "/"
  description = "role to allow EKS to access ECR"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:GetAuthorizationToken"
        ],
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_policy" "ssm-policy" {
  name        = "tf-managed-ssm-policy"
  path        = "/"
  description = "role to allow EKS to access ECR"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ssm:GetParametersByPath",
          "ssm:GetParameters",
          "ssm:GetParameter",
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:GetAuthorizationToken"
        ],
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_policy" "eks-autoscaling-policy" {
  name = "tf-managed-eks-autoscale-policy"
  path = "/"
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : [
            "autoscaling:DescribeAutoScalingGroups",
            "autoscaling:DescribeAutoScalingInstances",
            "autoscaling:DescribeLaunchConfigurations",
            "autoscaling:DescribeTags",
            "autoscaling:SetDesiredCapacity",
            "autoscaling:TerminateInstanceInAutoScalingGroup",
            "ec2:DescribeLaunchTemplateVersions"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        }
      ]
  })
}
resource "aws_iam_group_policy" "eks-admin-policy" {
  name  = "tf-managed-eks-admin-policy"
  group = aws_iam_group.eks-admins.id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "eks:*"
        ],
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_policy" "eks-assume-role-policy" {
  name = "tf-managed-eks-assume-role-policy"
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : "sts:AssumeRole",
          "Resource" : "*"
        }
      ]
  })
}

resource "aws_iam_role" "pod-assume-role" {
  name = "tf-managed-aws_eks_pod_assume_role"
  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : "sts:AssumeRole",
          "Principal" : {
            "Service" : "ec2.amazonaws.com"
          },
          "Effect" : "Allow",
          "Sid" : ""
        },
        {
          "Sid" : "",
          "Effect" : "Allow",
          "Principal" : {
            "AWS" : aws_iam_role.eks-node-group-role.arn
          },
          "Action" : "sts:AssumeRole"
        }
      ]
    }
  )
}

resource "aws_iam_group" "eks-admins" {
  name = "tf-managed-eks-admins"
}

resource "aws_iam_user" "k8s-users" {
  count = length(var.k8s-user-names)
  name  = var.k8s-user-names[count.index]

}

resource "aws_iam_group_membership" "eks-admin-team-membership" {
  name  = "tf-testing-group-membership"
  users = aws_iam_user.k8s-users.*.name
  group = aws_iam_group.eks-admins.name
}

resource "aws_iam_openid_connect_provider" "example" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = []
  url             = aws_eks_cluster.base-cluster.identity.0.oidc.0.issuer
}

resource "aws_iam_role" "ssm-reader" {
  name = "tf-managed-ssm-reader"
  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          Effect : "Allow",
          Principal : {
            "AWS" : aws_iam_role.eks-node-group-role.arn
          },
          Action : "sts:AssumeRole"
        }
      ]
  })
}

resource "aws_iam_role" "basic-pod-role" {
  name = "tf-managed-basic-pod-role"
  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          Sid: "",
          Effect: "Allow",
          Principal: {
            Service: "ec2.amazonaws.com"
          },
        Action: "sts:AssumeRole"
        },
        {
          Effect : "Allow",
          Principal : {
            "AWS" : aws_iam_role.eks-node-group-role.arn
          },
          Action : "sts:AssumeRole"
        }
      ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch-writer-attachment" {
  policy_arn = aws_iam_policy.cloudwatch-writer-policy.arn
  role       = aws_iam_role.basic-pod-role.name
}

resource "aws_iam_role_policy_attachment" "ssm-reader-attachment" {
  policy_arn = aws_iam_policy.ssm-policy.arn
  role       = aws_iam_role.basic-pod-role.name
}

resource "aws_iam_role_policy_attachment" "cloudwatch-reader-attachment-for-basic-pod-role" {
  policy_arn = aws_iam_policy.cloudwatch-read-policy.arn
  role       = aws_iam_role.basic-pod-role.name
}


resource "aws_iam_role_policy_attachment" "cloudwatch-reader-attachment" {
  policy_arn = aws_iam_policy.cloudwatch-read-policy.arn
  role       = aws_iam_role.cloudwatch-reader.name
}

resource "aws_iam_role" "cloudwatch-reader" {
  name = "tf-managed-cloudwatch-reader"
  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          Effect : "Allow",
          Principal : {
            "AWS" : aws_iam_role.eks-node-group-role.arn
          },
          Action : "sts:AssumeRole"
        }
      ]
  })
}

resource "aws_iam_policy" "cloudwatch-read-policy" {
  name = "tf-managed-cloudwatch-read-policy"
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Sid" : "AllowReadingMetricsFromCloudWatch",
          "Effect" : "Allow",
          "Action" : [
            "cloudwatch:DescribeAlarmsForMetric",
            "cloudwatch:DescribeAlarmHistory",
            "cloudwatch:DescribeAlarms",
            "cloudwatch:ListMetrics",
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:GetMetricData"
          ],
          "Resource" : "*"
        },
        {
          "Sid" : "AllowReadingLogsFromCloudWatch",
          "Effect" : "Allow",
          "Action" : [
            "logs:DescribeLogGroups",
            "logs:GetLogGroupFields",
            "logs:StartQuery",
            "logs:StopQuery",
            "logs:GetQueryResults",
            "logs:GetLogEvents"
          ],
          "Resource" : "*"
        },
        {
          "Sid" : "AllowReadingTagsInstancesRegionsFromEC2",
          "Effect" : "Allow",
          "Action" : ["ec2:DescribeTags", "ec2:DescribeInstances", "ec2:DescribeRegions"],
          "Resource" : "*"
        },
        {
          "Sid" : "AllowReadingResourcesForTags",
          "Effect" : "Allow",
          "Action" : "tag:GetResources",
          "Resource" : "*"
        }
      ]
  })
}

resource "aws_iam_policy" "cloudwatch-writer-policy" {
  name = "tf-managed-cloudwatch-writer-policy"
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogGroups"
          ],
          "Resource" : [
            "arn:aws:logs:*:*:*"
          ]
        }
      ]
    }
  )
}
