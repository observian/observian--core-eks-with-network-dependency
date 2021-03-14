data "aws_ssm_parameter" "windows_ami" {
  name = "/aws/service/ami-windows-latest/Windows_Server-2019-English-Core-EKS_Optimized-1.18/image_id"
}