# Sphinx CLI Tool

A comprehensive command-line interface for creating, manipulating, and processing Sphinx packets and Single Use Reply Blocks (SURBs) for ad-hoc anonymous communication networks.

NOTE that this tool can use any post quantum cryptographic NIKE or KEM from the [HPQC library](https://github.com/katzenpost/hpqc), which includes:

| NIKE: Non-Interactive Key Exchange |
|:---:|

| Primitive | HPQC name | security |
|  --------  |  -------  | -------  | 
| Classical Diffie-Hellman | "DH4096_RFC3526" | classic |
| X25519 | "X25519" | classic |
| X448 | "X448" | classic |
| Implementations of CTIDH | "ctidh511", "ctidh512", "ctidh1024", "ctidh2048" | post-quantum | 
| hybrid of CSIDH and X25519 | "NOBS_CSIDH-X25519 " | hybrid |
|hybrids of CTIDH with X25519 | "CTIDH511-X25519", "CTIDH512-X25519", "CTIDH1024-X25519" | hybrid |
| hybrids of CTIDH with X448 | "CTIDH512-X448", "CTIDH1024-X448", "CTIDH2048-X448"| hybrid |

__________

| KEM: Key Encapsulation Mechanism |
|:---:|


| Primitive | HPQC name | security |
|  --------  |  -------  | -------  | 
| ML-KEM-768| "MLKEM768" | post-quantum |
| XWING is a hybrid primitive that pre-combines ML-KEM-768 and X25519. Due to [security properties](https://eprint.iacr.org/2018/024) of our combiner, we also implement our own combination of the two below.| "XWING" | hybrid |
| The sntrup4591761 version of the NTRU cryptosystem. | "NTRUPrime"  | post-quantum |
| FrodoKEM-640-SHAKE |"FrodoKEM-640-SHAKE"| post-quantum|
| Various forms of the McEliece cryptosystem| "mceliece348864", "mceliece348864f", "mceliece460896", "mceliece460896f", "mceliece6688128", "mceliece6688128f", "mceliece6960119", "mceliece6960119f", "mceliece8192128", "mceliece8192128f" | post-quantum|
|A hybrid of ML-KEM-768 and X25519. The [KEM Combiners paper](https://eprint.iacr.org/2018/024.pdf) is the reason we implemented our own combination in addition to including XWING. |"MLKEM768-X25519"| hybrid |
|A hybrid of ML-KEM-768 and X448|"MLKEM768-X448"| hybrid |
|A hybrid of FrodoKEM-640-SHAKE and X448|"FrodoKEM-640-SHAKE-X448"| hybrid |
|A hybrid of NTRU and X448| "sntrup4591761-X448"| hybrid |
|Hybrids of the McEliece primitives and X25519| "mceliece348864-X25519", "mceliece348864f-X25519", "mceliece460896-X25519", "mceliece460896f-X25519", "mceliece6688128-X25519", "mceliece6688128f-X25519", "mceliece6960119-X25519", "mceliece6960119f-X25519", "mceliece8192128-X25519", "mceliece8192128f-X25519" | hybrid|


## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Commands](#commands)
  - [newpacket - Create Forward Packets](#newpacket---create-forward-packets)
  - [newsurb - Create SURBs](#newsurb---create-surbs)
  - [newpacketfromsurb - Create Reply Packets](#newpacketfromsurb---create-reply-packets)
  - [unwrap - Process Packets at Mix Nodes](#unwrap---process-packets-at-mix-nodes)
  - [decryptsurbpayload - Decrypt SURB Replies](#decryptsurbpayload---decrypt-surb-replies)
  - [createGeometry - Create Geometry Files](#creategeometry---create-geometry-files)
  - [genNodeID - Generate Node IDs](#gennodeid---generate-node-ids)
- [Configuration](#configuration)
  - [Geometry File Format](#geometry-file-format)
  - [Creating Geometry Files](#creating-geometry-files)
  - [Key File Formats](#key-file-formats)
- [Workflows](#workflows)
  - [Standalone SURB Communication](#1-standalone-surb-communication)
  - [Forward Packet with Embedded SURB](#2-forward-packet-with-embedded-surb)
- [Technical Details](#technical-details)
  - [Packet Format](#packet-format)
  - [Payload Format (with embedded SURB)](#payload-format-with-embedded-surb)
  - [SURB Components](#surb-components)
  - [SURB Keys File Format](#surb-keys-file-format)
- [Testing](#testing)
  - [Unit Tests](#unit-tests)
  - [Integration Tests](#integration-tests)
- [Examples](#examples)
  - [Running the Standalone SURB Test](#running-the-standalone-surb-test)
  - [Running the Forward Packet with Embedded SURB Test](#running-the-forward-packet-with-embedded-surb-test)
  - [Key Features Demonstrated](#key-features-demonstrated)
  - [SURB IDs and Key Management](#surb-ids-and-key-management)
  - [Command Output Examples](#command-output-examples)
- [License](#license)



## Overview

The Sphinx CLI tool implements the Sphinx packet format for anonymous communication, supporting both forward packets and reply mechanisms through SURBs. It provides complete functionality for:

- Creating forward Sphinx packets with optional embedded SURBs
- Generating standalone SURBs for reply mechanisms
- Unwrapping packets at mix nodes
- Creating reply packets from SURBs
- Decrypting SURB reply payloads
- Extracting embedded SURBs from forward packets

## Installation

```bash
cd cmd/sphinx
go build -o sphinx .
```

Or install directly:

```bash
go install github.com/katzenpost/katzenpost/cmd/sphinx@latest
```

## Getting Help

The sphinx tool provides comprehensive help through the fang CLI framework:

```bash
# Show main help and available commands
./sphinx --help

# Show help for a specific command
./sphinx newpacket --help
./sphinx newsurb --help

# Show version information
./sphinx --version

# Generate man pages (if mango feature is available)
./sphinx --man
```

## Commands

### `newpacket` - Create Forward Packets

Creates a new Sphinx packet for forward communication through a mixnet.

```bash
./sphinx newpacket [flags]
```

**Flags:**
- `--geometry FILE` - TOML geometry configuration file (required)
- `--payload FILE` - Payload file (default: stdin)
- `--output FILE` - Output packet file (default: stdout)
- `--hop HOP` - Hop specification: node_id_hex,public_key_pem_file (required, multiple)
- `--include-surb` - Embed a SURB in the packet payload
- `--surb-hop HOP` - SURB hop specification (required with --include-surb)
- `--output-surb-keys FILE` - SURB keys output file (required with --include-surb)

**Hop Format:** `node_id_hex,public_key_pem_file`

**Example:**
```bash
./sphinx newpacket \
  --geometry geometry.toml \
  --payload message.txt \
  --output packet.bin \
  --hop "abc123...,node1.pem" \
  --hop "def456...,node2.pem"
```

**With Embedded SURB:**
```bash
./sphinx newpacket \
  --geometry geometry.toml \
  --payload message.txt \
  --output packet.bin \
  --hop "abc123...,node1.pem" \
  --hop "def456...,node2.pem" \
  --include-surb \
  --surb-hop "789abc...,node3.pem" \
  --surb-hop "012def...,node4.pem" \
  --output-surb-keys reply.keys
```

### `newsurb` - Create SURBs

Creates a Single Use Reply Block for anonymous replies.

```bash
./sphinx newsurb [flags]
```

**Flags:**
- `--geometry FILE` - TOML geometry configuration file (required)
- `--output-surb FILE` - SURB output file (required)
- `--output-keys FILE` - SURB keys output file (required)
- `--hop HOP` - Hop specification: node_id_hex,public_key_pem_file (required, multiple)

**Example:**
```bash
./sphinx newsurb \
  --geometry geometry.toml \
  --output-surb reply.surb \
  --output-keys reply.keys \
  --hop "abc123...,node1.pem" \
  --hop "def456...,node2.pem"
```

**Output:**
- **SURB file**: Share with potential senders
- **First hop ID**: Share with potential senders
- **Keys file**: Keep private for decrypting replies

### `newpacketfromsurb` - Create Reply Packets

Creates a reply packet using a SURB.

```bash
./sphinx newpacketfromsurb [flags]
```

**Flags:**
- `--geometry FILE` - TOML geometry configuration file (required)
- `--surb FILE` - SURB file (required)
- `--payload FILE` - Payload file (default: stdin)
- `--output FILE` - Output packet file (default: stdout)

**Example:**
```bash
./sphinx newpacketfromsurb \
  --geometry geometry.toml \
  --surb reply.surb \
  --payload reply_message.txt \
  --output reply_packet.bin
```

### `unwrap` - Process Packets at Mix Nodes

Unwraps a Sphinx packet at a mix node, revealing routing commands and payload.

```bash
./sphinx unwrap [flags]
```

**Flags:**
- `--geometry FILE` - TOML geometry configuration file (required)
- `--private-key FILE` - Node's private key PEM file (required)
- `--packet FILE` - Input packet file (default: stdin)
- `--output FILE` - Payload output file (default: stdout)
- `--output-packet FILE` - Processed packet output file
- `--output-surb FILE` - Extract embedded SURB to file

**Example:**
```bash
./sphinx unwrap \
  --geometry geometry.toml \
  --private-key node1_private.pem \
  --packet input_packet.bin \
  --output-packet next_packet.bin \
  --output payload.bin
```

**Extract Embedded SURB:**
```bash
./sphinx unwrap \
  --geometry geometry.toml \
  --private-key node2_private.pem \
  --packet final_packet.bin \
  --output user_message.txt \
  --output-surb extracted.surb
```

### `decryptsurbpayload` - Decrypt SURB Replies

Decrypts a SURB reply payload using SURB keys.

```bash
./sphinx decryptsurbpayload [flags]
```

**Flags:**
- `--geometry FILE` - TOML geometry configuration file (required)
- `--keys FILE` - SURB keys file (required)
- `--payload FILE` - Encrypted payload file (default: stdin)
- `--output FILE` - Decrypted output file (default: stdout)

**Example:**
```bash
./sphinx decryptsurbpayload \
  --geometry geometry.toml \
  --keys reply.keys \
  --payload encrypted_reply.bin \
  --output decrypted_reply.txt
```

### `createGeometry` - Create Geometry Files

Creates a Sphinx geometry configuration file with calculated packet parameters.

```bash
./sphinx createGeometry [flags]
```

**Flags:**
- `--nike SCHEME` - NIKE scheme (e.g., x25519, x448)
- `--kem SCHEME` - KEM scheme (e.g., MLKEM768, kyber1024)
- `--nrMixLayers N` - Number of mix layers/hops (default: 3)
- `--UserForwardPayloadLength N` - User forward payload length (default: 2000)
- `--file FILE` - Output geometry file (empty for stdout)

**Examples:**
```bash
# Create geometry with NIKE scheme
./sphinx createGeometry --nike x25519 --nrMixLayers 2 --file geometry.toml

# Create geometry with KEM scheme
./sphinx createGeometry --kem MLKEM768 --nrMixLayers 3 --file geometry.toml

# Output to stdout
./sphinx createGeometry --nike x25519 --nrMixLayers 2
```

### `genNodeID` - Generate Node IDs

Generates a deterministic node ID from a public key file.

```bash
./sphinx genNodeID [flags]
```

**Flags:**
- `--key FILE` - Path to public key PEM file (required)

**Example:**
```bash
./sphinx genNodeID --key node1.nike_public.pem
```

## Configuration

### Geometry File Format

Geometry files define the Sphinx packet parameters and are **programmatically generated** by the Katzenpost system. They cannot be manually edited and must be obtained from the network configuration.

**Example geometry file structure:**
```toml
[SphinxGeometry]
PacketLength = 2590
HeaderLength = 230
RoutingInfoLength = 16
PerHopRoutingInfoLength = 16
SURBLength = 326
NrHops = 2
PayloadTagLength = 32
ForwardPayloadLength = 2328
UserForwardPayloadLength = 2000
NIKEName = "x25519"
KEMName = ""
```

**Important**: These values are calculated based on cryptographic parameters and network topology. Manual modification will result in incompatible packets.

### Creating Geometry Files

Geometry files are created using the `createGeometry` subcommand. The geometry defines all packet parameters for a specific network configuration.

**Create geometry with NIKE scheme:**
```bash
./sphinx createGeometry --nike x25519 --nrMixLayers 2 --file geometry.toml
```

**Create geometry with KEM scheme:**
```bash
./sphinx createGeometry --kem MLKEM768 --nrMixLayers 3 --file geometry.toml
```

**Network operators** typically generate geometry files as part of network configuration and distribute them to clients.

### Key File Formats

**Public Keys**: PEM format
**Private Keys**: PEM format
**SURB Keys**: TOML format with base64-encoded key data

## Workflows

### 1. Standalone SURB Communication

**Recipient creates SURB:**
```bash
./sphinx newsurb --geometry geo.toml --output-surb reply.surb --output-keys reply.keys --hop "..." --hop "..."
# Share: reply.surb + first_hop_id
# Keep: reply.keys
```

**Sender creates reply:**
```bash
./sphinx newpacketfromsurb --geometry geo.toml --surb reply.surb --payload message.txt --output packet.bin
# Send packet.bin to first_hop_id
```

**Recipient decrypts reply:**
```bash
./sphinx decryptsurbpayload --geometry geo.toml --keys reply.keys --payload final_payload.bin --output message.txt
```

### 2. Forward Packet with Embedded SURB

**Sender creates forward packet with embedded SURB:**
```bash
./sphinx newpacket --geometry geo.toml --payload msg.txt --output packet.bin \
  --hop "..." --hop "..." \
  --include-surb --surb-hop "..." --surb-hop "..." --output-surb-keys reply.keys
```

**Recipient extracts SURB and message:**
```bash
./sphinx unwrap --geometry geo.toml --private-key final_node.pem --packet packet.bin \
  --output user_message.txt --output-surb extracted.surb
```

**Recipient sends reply using extracted SURB:**
```bash
./sphinx newpacketfromsurb --geometry geo.toml --surb extracted.surb --payload reply.txt --output reply_packet.bin
```

**Original sender decrypts reply:**
```bash
./sphinx decryptsurbpayload --geometry geo.toml --keys reply.keys --payload final_reply.bin --output reply.txt
```

## Technical Details

### Packet Format

**Forward Packets:**
- Sphinx header (encrypted routing information)
- Payload (user data, optionally with embedded SURB)

**SURB Reply Packets:**
- Sphinx header (from SURB)
- Encrypted payload

### Payload Format (with embedded SURB)

```
[1 byte flags][1 byte reserved][SURB blob][user payload]
```

- `flags = 1`: SURB present
- `flags = 0`: No SURB
- `reserved = 0`: Always zero

### SURB Components

A SURB consists of:
1. **SURB blob**: Encrypted Sphinx header + first hop ID + encryption key
2. **First hop ID**: Where to send reply packets
3. **Decryption keys**: For decrypting replies (keep private)

### SURB Keys File Format

```toml
# SURB Keys File
# Generated by Sphinx CLI tool

surb_id = "7b6055d66b03e1dc3fab3381b701415a"

key_data = "base64_encoded_decryption_keys"
```

## Testing

### Unit Tests

Run the comprehensive unit test suite:

```bash
go test -v .                # Run unit tests with verbose output
./run_tests.sh             # Run both unit and integration tests
```


### Integration Tests

Run the included integration test scripts:

```bash
./examples/test_surb.sh              # Test standalone SURB workflow
./examples/test_forward_with_surb.sh # Test embedded SURB workflow
```

The integration test scripts automatically:
- Install the Sphinx CLI tool using `go install`
- Build the genkeypair tool for key generation
- Generate all required cryptographic keys
- Create appropriate geometry files
- Test complete end-to-end workflows with 5-hop paths

## Examples

### Running the Standalone SURB Test

```bash
$ ./examples/test_surb.sh
=== Testing Complete SURB Functionality ===
Installing Sphinx CLI tool...
Building genkeypair tool...
Generating test key files...
Generating geometry file...
1. Creating SURB...
SURB IDs created:
  Hop 0: 7b6055d66b03e1dc3fab3381b701415a
  Hop 1: d1a9c673ac5b394cc958e28a5e34b5e1
  Hop 2: c400dabf67ef00bf5654a00de40ea13e
  Hop 3: 6b957a7e3cb809f000216031d0c6dc0a
  Hop 4: 7d1d41f10b90b3cc8360ac4766420479
SURB created successfully!
SURB written to test_surb.surb (572 bytes)
SURB keys written to test_surb.keys (384 bytes)

To use this SURB, share these components:
  SURB file: test_surb.surb
  First hop ID: b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30

Keep private:
  Decryption keys: test_surb.keys

2. Creating reply message...

3. Creating packet from SURB...
Packet created from SURB successfully!
First hop node ID: b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30
Packet size: 3082 bytes
Packet written to test_reply.bin

4. Unwrapping packet (hop 1)...
Packet unwrapped successfully!
Commands found: 2
  Command 0: SURBReply 7b6055d66b03e1dc3fab3381b701415a
SURB_ID: 7b6055d66b03e1dc3fab3381b701415a
  Command 1: NextNodeHop to 2062050ca17fe7e4c0db07e8481b7c9e4e8196bf5cd0a0f7cfa8c08bb7e055ba

5. Unwrapping packet (hop 2)...
Packet unwrapped successfully!
Commands found: 2
  Command 0: SURBReply d1a9c673ac5b394cc958e28a5e34b5e1
SURB_ID: d1a9c673ac5b394cc958e28a5e34b5e1
  Command 1: NextNodeHop to 8e0cc4461f928837c4937458c52279d4a2c33ee440be41261a05cb128484c2d2

[... continues through all 5 hops ...]

8. Unwrapping packet (hop 5 - final)...
Packet unwrapped successfully!
Commands found: 1
  Command 0: SURBReply 7d1d41f10b90b3cc8360ac4766420479
SURB_ID: 7d1d41f10b90b3cc8360ac4766420479

This is the final hop (no next hop)
Payload size: 2606 bytes

9. Decrypting SURB payload...
SURB payload decrypted successfully!
Decrypted payload size: 2574 bytes

10. Verifying result...
Original message:
Hello from SURB reply test!

Decrypted message:
Hello from SURB reply test!

=== SURB Test Complete ===
```

### Running the Forward Packet with Embedded SURB Test

```bash
$ ./examples/test_forward_with_surb.sh
=== Testing Forward Packet with Embedded SURB + SURB Reply ===
Installing Sphinx CLI tool...
Building genkeypair tool...
Generating test key files...
Generating geometry file...
1. Creating forward packet with embedded SURB...
SURB IDs created:
  Hop 0: e5b19d1759006b0d02cadd604363641f
  Hop 1: d8ec8d8dc9a4b53017d427edbfe79f71
  Hop 2: 83989b21f42e9377f4f7c008ad8ba574
  Hop 3: 15db45ce22f917911f839bbd64a5423b
  Hop 4: 5ade28082a34c10e2a4760cdddb20e7f
SURB embedded in packet payload
SURB keys written to forward_surb.keys (384 bytes)
Sphinx packet written to forward_with_surb.bin (3082 bytes)

2. Unwrapping forward packet (hop 1)...
Packet unwrapped successfully!
Commands found: 1
  Command 0: NextNodeHop to 2062050ca17fe7e4c0db07e8481b7c9e4e8196bf5cd0a0f7cfa8c08bb7e055ba

[... continues through all 5 forward hops ...]

6. Unwrapping forward packet (hop 5 - final destination)...
Packet unwrapped successfully!
Commands found: 1
  Command 0: Recipient 0000000000000000000000000000000000000000000000000000000000000000

This is the final hop (no next hop)
Payload size: 2574 bytes
SURB extracted successfully!
SURB written to extracted_surb.surb (572 bytes)
User payload size: 2000 bytes

7. Checking if SURB was extracted...
✅ SURB successfully extracted to extracted_surb.surb

9. Creating reply message using the embedded SURB...
Creating a test SURB for reply demonstration...
SURB created successfully!

10. Creating reply packet from SURB...
Packet created from SURB successfully!
Packet size: 3082 bytes

[... continues through all 5 reply hops ...]

16. Decrypting SURB reply payload...
SURB payload decrypted successfully!

17. Verifying complete workflow...
=== FORWARD MESSAGE ===
Original forward message:
Original message for forward packet

=== REPLY MESSAGE ===
Original reply message:
This is a reply using the embedded SURB!

Decrypted reply message:
This is a reply using the embedded SURB!

=== WORKFLOW SUMMARY ===
✅ Forward packet with embedded SURB created
✅ Forward packet routed through 5 hops
✅ Combined payload (message + SURB) delivered
✅ Reply SURB used to create return packet
✅ Reply packet routed back through different 5-hop path
✅ Reply message successfully decrypted

=== Test Complete ===
```

### Key Features Demonstrated

**SURB ID Tracking**: Each hop shows unique SURB IDs for proper key management
**5-Hop Paths**: Both forward and reverse paths use 5 hops for enhanced security
**Automatic Setup**: Scripts handle all tool installation and key generation
**Complete Workflows**: End-to-end testing of all Sphinx functionality
**SURB Extraction**: Automatic extraction of embedded SURBs from forward packets
**Bidirectional Communication**: Full round-trip message exchange

### SURB IDs and Key Management

Each hop in a SURB path has a unique SURB ID that appears in:
1. **SURB creation output**: Shows which SURB ID corresponds to each hop
2. **Packet unwrapping**: Displays SURB ID when SURBReply commands are found
3. **Key files**: Maps SURB IDs to decryption keys

**Example SURB ID output:**
```
SURB IDs created:
  Hop 0: f2250faaac35d6970115562d8b9b5f42
  Hop 1: d543051418101050faf72f8f1f170709
```

**Example unwrap output:**
```
Commands found: 2
  Command 0: SURBReply f2250faaac35d6970115562d8b9b5f42
  SURB_ID: f2250faaac35d6970115562d8b9b5f42
  Command 1: NextNodeHop to 2062050ca17fe7e4c0db07e8481b7c9e4e8196bf5cd0a0f7cfa8c08bb7e055ba
```

### Command Output Examples

**Successful packet creation:**
```
Sphinx packet written to packet.bin (2590 bytes)
```

**Successful SURB creation:**
```
SURB created successfully!
SURB written to reply.surb (326 bytes)
SURB keys written to reply.keys (192 bytes)

To use this SURB, share these components:
  SURB file: reply.surb
  First hop ID: b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30

Keep private:
  Decryption keys: reply.keys
```

**Successful SURB extraction:**
```
SURB extracted successfully!
SURB written to extracted.surb (326 bytes)
User payload size: 2000 bytes
```

## License

AGPL v3 - See LICENSE file for details.
