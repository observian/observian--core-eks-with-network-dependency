resource "aws_key_pair" "windows_ssh_key" {
    key_name = "windows_ssh_key"
    public_key = var.public_key
}