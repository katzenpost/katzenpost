#export AWS_PROFILE=personal
#
#aws s3 ls
#aws ec2 describe-instances

#terraform init
#terraform plan -var-file="terraform.tfvars"
terraform apply -var-file="terraform.tfvars" --auto-approve

cp hosts_builder.ini hosts_mixnet.ini ..
