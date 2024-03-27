output "mix_nodes_ips" {
  value = aws_instance.mix_nodes[*].public_ip
}

output "provider_nodes_ips" {
  value = aws_instance.provider_nodes[*].public_ip
}

output "dirauth_nodes_ips" {
  value = aws_instance.dirauth_nodes[*].public_ip
}

output "katzenpost_builder_public_ip" {
  value = aws_instance.katzenpost_builder.public_ip
  description = "The public IP address of the Katzenpost builder instance."
}
