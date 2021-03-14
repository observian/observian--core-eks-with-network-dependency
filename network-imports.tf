data "aws_vpc" "base-app-vpc" {
    filter {
        name = "tag:Name"
        values = ["ob-eks-demo-dev-vpc"]
    }
}
data "aws_subnet" "base-app-public-alpha" {
    filter {
        name = "tag:Name"
        values = ["*-public-alpha"]
    }
}

data "aws_subnet" "base-app-public-bravo" {
    filter {
        name = "tag:Name"
        values = ["*-public-bravo"]
    }
}

data "aws_subnet" "base-app-private-bravo" {
    filter {
        name = "tag:Name"
        values = ["*-private-bravo"]
    }
}

data "aws_subnet" "base-app-private-alpha" {
    filter {
        name = "tag:Name"
        values = ["*-private-alpha"]
    }
}