variable "eks_clsuter_name" {
}

variable "application" {
}

variable "env" {
}

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
