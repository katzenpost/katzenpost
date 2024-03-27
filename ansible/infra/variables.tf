variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "profile" {
    description = "AWS profile"
    type        = string
    default     = "personal"
}

variable "ami" {
  description = "AMI ID for the instances"
  type        = string
}

variable "key_name" {
  description = "SSH key pair name"
  type        = string
}

variable "mix_nodes_count" {
  description = "Number of mix nodes"
  type        = number
  default     = 3
}

variable "provider_nodes_count" {
  description = "Number of provider nodes"
  type        = number
  default     = 2
}

variable "dirauth_nodes_count" {
  description = "Number of dirauth nodes"
  type        = number
  default     = 3
}
