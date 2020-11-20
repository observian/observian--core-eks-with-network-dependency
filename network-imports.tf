data "aws_vpc" "base-app-vpc" {
    filter {
        name = "tag:Name"
        values = ["${var.application}-${var.env}-vpc"]
    }
}
data "aws_subnet" "base-app-public-alpha" {
    filter {
        name = "tag:Name"
        values = ["${var.application}-${var.env}-public-alpha"]
    }
}

data "aws_subnet" "base-app-public-bravo" {
    filter {
        name = "tag:Name"
        values = ["${var.application}-${var.env}-public-bravo"]
    }
}

data "aws_subnet" "base-app-private-bravo" {
    filter {
        name = "tag:Name"
        values = ["${var.application}-${var.env}-private-bravo"]
    }
}

data "aws_subnet" "base-app-private-alpha" {
    filter {
        name = "tag:Name"
        values = ["${var.application}-${var.env}-private-alpha"]
    }
}