# Sphinx CLI Tool

A comprehensive command-line interface for creating, manipulating, and processing Sphinx packets and Single Use Reply Blocks (SURBs) for ad-hoc anonymous communication networks.

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
- [SURB IDs and Key Management](#surb-ids-and-key-management)
- [Command Output Examples](#command-output-examples)
- [Testing](#testing)
- [Advanced Usage](#advanced-usage)
  - [Network Geometries](#network-geometries)
  - [Batch Processing](#batch-processing)
  - [Integration with Mix Networks](#integration-with-mix-networks)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
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
cd core/sphinx/cmd/sphinx
go build -o sphinx .
```

## Commands

### `newpacket` - Create Forward Packets

Creates a new Sphinx packet for forward communication through a mixnet.

```bash
./sphinx newpacket [flags] hop1 hop2 ... hopN
```

**Flags:**
- `--geometry FILE` - TOML geometry configuration file (required)
- `--payload FILE` - Payload file (default: stdin)
- `--output FILE` - Output packet file (default: stdout)
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
  --hop="abc123...,node1.pem" \
  --hop="def456...,node2.pem"
```

**With Embedded SURB:**
```bash
./sphinx newpacket \
  --geometry geometry.toml \
  --payload message.txt \
  --output packet.bin \
  --hop="abc123...,node1.pem" \
  --hop="def456...,node2.pem" \
  --include-surb \
  --surb-hop="789abc...,node3.pem" \
  --surb-hop="012def...,node4.pem" \
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
- `--hop HOP` - Hop specification (required, multiple)

**Example:**
```bash
./sphinx newsurb \
  --geometry geometry.toml \
  --output-surb reply.surb \
  --output-keys reply.keys \
  --hop="abc123...,node1.pem" \
  --hop="def456...,node2.pem"
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
- `--kem SCHEME` - KEM scheme (e.g., kyber768, kyber1024)
- `--hops N` - Number of hops in the path (required)
- `--output FILE` - Output geometry file (required)

**Example:**
```bash
./sphinx createGeometry --nike x25519 --hops 2 --output geometry.toml
```

### `genNodeID` - Generate Node IDs

Generates a deterministic node ID from a public key file.

```bash
./sphinx genNodeID public_key.pem
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
./sphinx createGeometry --nike x25519 --hops 2 --output geometry.toml
```

**Create geometry with KEM scheme:**
```bash
./sphinx createGeometry --kem kyber768 --hops 3 --output geometry.toml
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
./sphinx newsurb --geometry geo.toml --output-surb reply.surb --output-keys reply.keys --hop="..." --hop="..."
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
  --hop="..." --hop="..." \
  --include-surb --surb-hop="..." --surb-hop="..." --output-surb-keys reply.keys
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
surb_ids = [
  "hop0_surb_id_hex",
  "hop1_surb_id_hex"
]

key_data = "base64_encoded_decryption_keys"
```

## Testing

Run the included test scripts from the examples directory:

```bash
./examples/test_surb.sh              # Test standalone SURB workflow
./examples/test_forward_with_surb.sh # Test embedded SURB workflow
```

The test scripts automatically:
- Install the Sphinx CLI tool using `go install`
- Build the genkeypair tool for key generation
- Generate all required cryptographic keys
- Create appropriate geometry files
- Test complete end-to-end workflows with 5-hop paths

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
