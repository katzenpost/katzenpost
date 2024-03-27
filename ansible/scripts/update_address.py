import os
from configparser import ConfigParser

port = 8080

# Define the path to the directory containing the TOML files
directory_path = "voting_mixnet"

# Define the path to the hosts_mixnet.ini file
hosts_mixnet_path = "hosts_mixnet.ini"

# Parse the hosts_mixnet.ini to get new addresses
config = ConfigParser()
config.read(hosts_mixnet_path)

new_addresses = {}
for section in config.sections():
    addr = []
    for key, value in config.items(section):
        ip = key.split(" ")[0]
        new_address = f"{ip}:{port}"
        addr.append(new_address)
    new_addresses[section] = addr


# Initialize starting port and address_mapping
default_address = "127.0.0.1"
start_port = 30001
address_mapping = {}

# dirauth_nodes
for address in new_addresses['dirauth_nodes']:
    old_address = f"{default_address}:{start_port}"
    address_mapping[old_address] = address
    start_port += 1  # Increment by 1 for dirauth_nodes

# provider_nodes
for i, address in enumerate(new_addresses['provider_nodes']):
    # Main service port
    old_address = f"{default_address}:{start_port}"
    address_mapping[old_address] = address
    start_port += 1  # Increment to skip to the metrics port
    # Metrics port, skipped in mapping, just increment start_port
    old_metrics_address = f"{default_address}:{start_port}"
    address_mapping[old_metrics_address] = old_metrics_address
    start_port += 1

# mix_nodes
for i, address in enumerate(new_addresses['mix_nodes']):
    # Main service port
    old_address = f"{default_address}:{start_port}"
    address_mapping[old_address] = address
    start_port += 1  # Increment to skip to the metrics port

    old_metrics_address = f"{default_address}:{start_port}"
    address_mapping[old_metrics_address] = old_metrics_address
    start_port += 1



# Function to update all .toml files in a directory
def update_toml_files(directory_path, address_mapping):
    for root, dirs, files in os.walk(directory_path):
        for name in files:
            if name.endswith(".toml"):
                file_path = os.path.join(root, name)
                with open(file_path, 'r') as file:
                    file_contents = file.read()

                # Replace all occurrences of each address
                for old_address, new_address in address_mapping.items():
                    file_contents = file_contents.replace(old_address, new_address)

                # Write the updated contents back to the file
                with open(file_path, 'w') as file:
                    file.write(file_contents)

# Update all .toml files
update_toml_files(directory_path, address_mapping)