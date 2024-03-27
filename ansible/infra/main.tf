provider "aws" {
  region = var.region
  profile = var.profile
}

resource "aws_security_group" "ssh_and_internal" {
  name        = "ssh_and_internal"
  description = "Allow SSH, tcp on 8080 and internal VPC traffic"

  # Allow SSH from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow tcp traffic on port 8080 from anywhere
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all traffic within the VPC
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "katzenpost_builder" {
  ami           = var.ami
  instance_type = "t2.medium"
  key_name      = var.key_name
  security_groups = [aws_security_group.ssh_and_internal.name]

  tags = {
    Name = "katzenpost-builder"
  }
}

resource "aws_instance" "mix_nodes" {
  count         = var.mix_nodes_count
  ami           = var.ami
  instance_type = "t2.micro"
  key_name      = var.key_name
  security_groups = [aws_security_group.ssh_and_internal.name]

  tags = {
    Name = "mix-node-${count.index}"
    Role = "MixNode"
  }
}

resource "aws_instance" "provider_nodes" {
  count         = var.provider_nodes_count
  ami           = var.ami
  instance_type = "t2.micro"
  key_name      = var.key_name
  security_groups = [aws_security_group.ssh_and_internal.name]

  tags = {
    Name = "provider-node-${count.index}"
    Role = "ProviderNode"
  }
}

resource "aws_instance" "dirauth_nodes" {
  count         = var.dirauth_nodes_count
  ami           = var.ami
  instance_type = "t2.micro"
  key_name      = var.key_name
  security_groups = [aws_security_group.ssh_and_internal.name]

  tags = {
    Name = "dirauth-node-${count.index}"
    Role = "DirauthNode"
  }
}

resource "local_file" "ansible_hosts_mixnet" {
  content = <<-EOF
[mix_nodes]
${join("\n", formatlist("%s ansible_ssh_private_key_file=${var.key_name}.pem ansible_ssh_user=ubuntu", aws_instance.mix_nodes[*].public_ip))}
[provider_nodes]
${join("\n", formatlist("%s ansible_ssh_private_key_file=${var.key_name}.pem ansible_ssh_user=ubuntu", aws_instance.provider_nodes[*].public_ip))}
[dirauth_nodes]
${join("\n", formatlist("%s ansible_ssh_private_key_file=${var.key_name}.pem ansible_ssh_user=ubuntu", aws_instance.dirauth_nodes[*].public_ip))}
EOF

  filename = "${path.module}/hosts_mixnet.ini"
}

resource "local_file" "ansible_hosts_builder" {
  content = <<-EOF
[katzenpost_builder]
${aws_instance.katzenpost_builder.public_ip} ansible_ssh_private_key_file=${var.key_name}.pem ansible_ssh_user=ubuntu
EOF

  filename = "${path.module}/hosts_builder.ini"
}
