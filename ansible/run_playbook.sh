
#brew install ansible


#chmod 400 katzenpost-ansible.pem
#ssh -i "katzenpost-ansible.pem" ubuntu@100.24.67.47
export ANSIBLE_HOST_KEY_CHECKING=False

###### build mix_net #####
#ansible-playbook -i hosts_builder.ini playbooks/build_and_configure.yml

##### deploy mix_net #####
ansible-playbook -i hosts_mixnet.ini playbooks/deploy_mixnet.yml

#### clear artifacts ####
rm -rf playbooks/artifacts
