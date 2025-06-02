// SPDX-FileCopyrightText: Copyright (C) 2025  David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikepem "github.com/katzenpost/hpqc/nike/pem"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type CreateGeometry struct {
	NrMixHops                int
	NIKE                     string
	KEM                      string
	UserForwardPayloadLength int
	File                     string
}

type NewPacket struct {
	GeometryFile string
	OutputFile   string
	PayloadFile  string
	Path         []*sphinx.PathHop
}

type NodeSpec struct {
	NodeID        [constants.NodeIDLength]byte
	NIKEPublicKey nike.PublicKey
	KEMPublicKey  kem.PublicKey
	RecipientID   [constants.RecipientIDLength]byte
}

var rootCmd = &cobra.Command{
	Use:   "sphinx",
	Short: "Sphinx packet manipulation tool",
	Long:  "A CLI tool for creating and manipulating Sphinx packets for composing ad-hoc mixnets.",
}

var createGeometryCmd = &cobra.Command{
	Use:   "createGeometry",
	Short: "Generate Sphinx geometry configuration",
	Long:  "Generate a Sphinx geometry configuration and write it to a TOML file or stdout.",
	Run: func(cmd *cobra.Command, args []string) {
		var createGeometry CreateGeometry

		// Get flag values
		createGeometry.NrMixHops, _ = cmd.Flags().GetInt("nrMixLayers")
		createGeometry.KEM, _ = cmd.Flags().GetString("kem")
		createGeometry.NIKE, _ = cmd.Flags().GetString("nike")
		createGeometry.UserForwardPayloadLength, _ = cmd.Flags().GetInt("UserForwardPayloadLength")
		createGeometry.File, _ = cmd.Flags().GetString("file")

		generateSphinxGeometry(&createGeometry)
	},
}

var newPacketCmd = &cobra.Command{
	Use:   "newpacket",
	Short: "Create a new Sphinx packet",
	Long: `Create a new Sphinx packet using the specified geometry and path.

Specify path hops using --hop flags in order. Each hop should be in the format:
  node_id_hex,public_key_pem_file

All hops use the same format. The final hop will automatically include a blank recipient command.

Example:
  sphinx newpacket --geometry config.toml \
    --hop "abc123...,node1_key.pem" \
    --hop "789abc...,node2_key.pem" \
    --hop "345678...,node3_key.pem" \
    --hop "fedcba...,node4_key.pem" \
    --hop "111222...,node5_key.pem"`,
	Run: func(cmd *cobra.Command, args []string) {
		var newPacket NewPacket

		// Get flag values
		newPacket.GeometryFile, _ = cmd.Flags().GetString("geometry")
		newPacket.OutputFile, _ = cmd.Flags().GetString("output")
		newPacket.PayloadFile, _ = cmd.Flags().GetString("payload")
		hops, _ := cmd.Flags().GetStringArray("hop")

		// Build path from hop specifications
		err := buildPathFromHops(&newPacket, hops)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		generateSphinxPacket(&newPacket)
	},
}

var genNodeIDCmd = &cobra.Command{
	Use:   "genNodeID",
	Short: "Generate node ID from public key file",
	Long: `Generate a deterministic node ID from a public key PEM file.
This is useful for creating hop specifications for the newpacket command.

Example:
  sphinx genNodeID --key node1.nike_public.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		keyFile, _ := cmd.Flags().GetString("key")
		if keyFile == "" {
			fmt.Fprintf(os.Stderr, "Error: --key flag is required\n")
			os.Exit(1)
		}
		generateNodeID(keyFile)
	},
}

var unwrapCmd = &cobra.Command{
	Use:   "unwrap",
	Short: "Unwrap/decrypt a Sphinx packet",
	Long: `Unwrap a Sphinx packet using a private key, revealing the payload and routing commands.
This simulates what a mix node does when processing a Sphinx packet.

Example:
  sphinx unwrap --geometry config.toml --private-key node1.nike_private.pem --packet packet.bin
  sphinx unwrap --geometry config.toml --private-key node1.nike_private.pem --packet packet.bin --output-packet next_packet.bin`,
	Run: func(cmd *cobra.Command, args []string) {
		geometryFile, _ := cmd.Flags().GetString("geometry")
		privateKeyFile, _ := cmd.Flags().GetString("private-key")
		packetFile, _ := cmd.Flags().GetString("packet")
		outputFile, _ := cmd.Flags().GetString("output")
		outputPacketFile, _ := cmd.Flags().GetString("output-packet")

		unwrapSphinxPacket(geometryFile, privateKeyFile, packetFile, outputFile, outputPacketFile)
	},
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(createGeometryCmd)
	rootCmd.AddCommand(newPacketCmd)
	rootCmd.AddCommand(genNodeIDCmd)
	rootCmd.AddCommand(unwrapCmd)

	// createGeometry flags
	createGeometryCmd.Flags().Int("nrMixLayers", 3, "number of hops per route not counting ingress/egress nodes")
	createGeometryCmd.Flags().String("kem", "", "Name of the KEM Scheme to be used with Sphinx")
	createGeometryCmd.Flags().String("nike", "x25519", "Name of the NIKE Scheme to be used with Sphinx")
	createGeometryCmd.Flags().Int("UserForwardPayloadLength", 2000, "UserForwardPayloadLength")
	createGeometryCmd.Flags().String("file", "", "file path to write TOML output to, empty indicates stdout")

	// newpacket flags
	newPacketCmd.Flags().String("geometry", "", "path to TOML geometry config file (required)")
	newPacketCmd.Flags().String("output", "", "file to write the Sphinx packet to (default: stdout)")
	newPacketCmd.Flags().String("payload", "", "file to read payload from (default: stdin)")
	newPacketCmd.Flags().StringArray("hop", []string{}, "hop specification: node_id_hex,public_key_pem_file (can be specified multiple times)")

	// genNodeID flags
	genNodeIDCmd.Flags().String("key", "", "path to public key PEM file (required)")

	// unwrap flags
	unwrapCmd.Flags().String("geometry", "", "path to TOML geometry config file (required)")
	unwrapCmd.Flags().String("private-key", "", "path to private key PEM file (required)")
	unwrapCmd.Flags().String("packet", "", "path to Sphinx packet file (required)")
	unwrapCmd.Flags().String("output", "", "file to write unwrapped payload to (default: stdout)")
	unwrapCmd.Flags().String("output-packet", "", "file to write the processed packet to (for forwarding to next hop)")

	// Mark required flags
	newPacketCmd.MarkFlagRequired("geometry")
	newPacketCmd.MarkFlagRequired("hop")
	genNodeIDCmd.MarkFlagRequired("key")
	unwrapCmd.MarkFlagRequired("geometry")
	unwrapCmd.MarkFlagRequired("private-key")
	unwrapCmd.MarkFlagRequired("packet")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func generateSphinxGeometry(createGeometry *CreateGeometry) {
	nrHops := createGeometry.NrMixHops + 2
	var sphinxGeometry *geo.Geometry
	if createGeometry.NIKE != "" {
		nikeScheme := schemes.ByName(createGeometry.NIKE)
		if nikeScheme == nil {
			log.Fatalf("failed to resolve nike scheme %s", createGeometry.NIKE)
		}
		sphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			createGeometry.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if createGeometry.KEM != "" {
		kemScheme := kemschemes.ByName(createGeometry.KEM)
		if kemScheme == nil {
			log.Fatalf("failed to resolve kem scheme %s", createGeometry.KEM)
		}
		sphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			createGeometry.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	tomlOut := sphinxGeometry.Display()
	if createGeometry.File == "" {
		fmt.Println(tomlOut)
	} else {
		out, err := os.OpenFile(createGeometry.File, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		writeCount, err := out.Write([]byte(tomlOut))
		if err != nil {
			panic(err)
		}
		if writeCount != len(tomlOut) {
			panic("partial write failure")
		}
		err = out.Sync()
		if err != nil {
			panic(err)
		}
		err = out.Close()
		if err != nil {
			panic(err)
		}
	}
}

// unwrapSphinxPacket unwraps a Sphinx packet using a private key
func unwrapSphinxPacket(geometryFile, privateKeyFile, packetFile, outputFile, outputPacketFile string) {
	// Load geometry from TOML file
	geometry, err := loadGeometryFromTOML(geometryFile)
	if err != nil {
		log.Fatalf("failed to load geometry: %v", err)
	}

	// Create Sphinx instance from geometry
	sphinx, err := sphinx.FromGeometry(geometry)
	if err != nil {
		log.Fatalf("failed to create Sphinx instance: %v", err)
	}

	// Load private key from PEM file
	var privateKey interface{}
	if geometry.NIKEName != "" {
		nikeScheme := schemes.ByName(geometry.NIKEName)
		if nikeScheme == nil {
			log.Fatalf("failed to resolve NIKE scheme: %s", geometry.NIKEName)
		}

		privKey, err := nikepem.FromPrivatePEMFile(privateKeyFile, nikeScheme)
		if err != nil {
			log.Fatalf("failed to load NIKE private key from %s: %v", privateKeyFile, err)
		}
		privateKey = privKey
	} else if geometry.KEMName != "" {
		kemScheme := kemschemes.ByName(geometry.KEMName)
		if kemScheme == nil {
			log.Fatalf("failed to resolve KEM scheme: %s", geometry.KEMName)
		}

		privKey, err := kempem.FromPrivatePEMFile(privateKeyFile, kemScheme)
		if err != nil {
			log.Fatalf("failed to load KEM private key from %s: %v", privateKeyFile, err)
		}
		privateKey = privKey
	} else {
		log.Fatalf("geometry has neither NIKE nor KEM scheme")
	}

	// Read packet from file
	packet, err := os.ReadFile(packetFile)
	if err != nil {
		log.Fatalf("failed to read packet file %s: %v", packetFile, err)
	}

	// Unwrap the packet
	payload, replayTag, cmds, err := sphinx.Unwrap(privateKey, packet)
	if err != nil {
		log.Fatalf("failed to unwrap Sphinx packet: %v", err)
	}

	// Print information about the unwrapped packet
	fmt.Fprintf(os.Stderr, "Packet unwrapped successfully!\n")
	fmt.Fprintf(os.Stderr, "Replay tag: %x\n", replayTag)
	fmt.Fprintf(os.Stderr, "Commands found: %d\n", len(cmds))

	var nextHopNodeID string
	var recipientID string
	for i, cmd := range cmds {
		switch c := cmd.(type) {
		case *commands.NextNodeHop:
			nextHopNodeID = hex.EncodeToString(c.ID[:])
			fmt.Fprintf(os.Stderr, "  Command %d: NextNodeHop to %s\n", i, nextHopNodeID)
		case *commands.Recipient:
			recipientID = hex.EncodeToString(c.ID[:])
			fmt.Fprintf(os.Stderr, "  Command %d: Recipient %s\n", i, recipientID)
		case *commands.SURBReply:
			fmt.Fprintf(os.Stderr, "  Command %d: SURBReply %x\n", i, c.ID[:])
		default:
			fmt.Fprintf(os.Stderr, "  Command %d: Unknown command type\n", i)
		}
	}

	// Print next hop information prominently
	if nextHopNodeID != "" {
		fmt.Fprintf(os.Stderr, "\nNext hop node ID: %s\n", nextHopNodeID)
	} else {
		fmt.Fprintf(os.Stderr, "\nThis is the final hop (no next hop)\n")
	}

	// Print recipient information if present
	if recipientID != "" {
		fmt.Fprintf(os.Stderr, "Recipient ID: %s\n", recipientID)
	}

	if len(payload) > 0 {
		fmt.Fprintf(os.Stderr, "Payload size: %d bytes\n", len(payload))

		// Write payload to output
		if outputFile == "" {
			// Write to stdout
			_, err = os.Stdout.Write(payload)
			if err != nil {
				log.Fatalf("failed to write payload to stdout: %v", err)
			}
		} else {
			// Write to file
			err = os.WriteFile(outputFile, payload, 0644)
			if err != nil {
				log.Fatalf("failed to write payload to file: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Payload written to %s\n", outputFile)
		}
	}

	// Save the processed packet if requested (for forwarding to next hop)
	if outputPacketFile != "" {
		err = os.WriteFile(outputPacketFile, packet, 0644)
		if err != nil {
			log.Fatalf("failed to write processed packet to file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Processed packet written to %s (%d bytes)\n", outputPacketFile, len(packet))
	}
}

// generateNodeID creates a deterministic node ID from a public key file
func generateNodeID(keyFile string) {
	// Read the PEM file
	pemData, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("failed to read key file %s: %v", keyFile, err)
	}

	// Generate a deterministic node ID by hashing the PEM data
	hash := sha256.Sum256(pemData)
	nodeID := hex.EncodeToString(hash[:])

	fmt.Printf("Node ID for %s: %s\n", keyFile, nodeID)
}

// loadGeometryFromTOML loads Sphinx geometry from a TOML config file
func loadGeometryFromTOML(filename string) (*geo.Geometry, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read geometry file: %w", err)
	}

	var config geo.Config
	err = toml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TOML: %w", err)
	}

	if config.SphinxGeometry == nil {
		return nil, fmt.Errorf("no SphinxGeometry section found in config")
	}

	// Validate the geometry
	err = config.SphinxGeometry.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid geometry: %w", err)
	}

	return config.SphinxGeometry, nil
}

// buildPathFromHops builds the Sphinx path from hop specifications
func buildPathFromHops(newPacket *NewPacket, hops []string) error {
	if len(hops) == 0 {
		return fmt.Errorf("no hops specified")
	}

	// Load geometry to know which scheme to use and validate hop count
	geometry, err := loadGeometryFromTOML(newPacket.GeometryFile)
	if err != nil {
		return fmt.Errorf("failed to load geometry: %v", err)
	}

	if len(hops) != geometry.NrHops {
		return fmt.Errorf("sphinx paths require exactly %d hops for this geometry, got %d", geometry.NrHops, len(hops))
	}

	// Build the path
	newPacket.Path = make([]*sphinx.PathHop, len(hops))

	for i, hopSpec := range hops {
		parts := strings.Split(hopSpec, ",")

		// All hops: node_id,public_key_file
		if len(parts) != 2 {
			return fmt.Errorf("hop %d: expected format 'node_id_hex,public_key_pem_file', got %d parts", i, len(parts))
		}

		nodeID := strings.TrimSpace(parts[0])
		publicKeyFile := strings.TrimSpace(parts[1])

		hop := &sphinx.PathHop{}

		// Parse node ID
		nodeIDBytes, err := hex.DecodeString(nodeID)
		if err != nil {
			return fmt.Errorf("hop %d: invalid node ID: %v", i, err)
		}
		if len(nodeIDBytes) != constants.NodeIDLength {
			return fmt.Errorf("hop %d: node ID has wrong length: got %d, expected %d", i, len(nodeIDBytes), constants.NodeIDLength)
		}
		copy(hop.ID[:], nodeIDBytes)

		// Load public key from PEM file based on geometry
		if geometry.NIKEName != "" {
			nikeScheme := schemes.ByName(geometry.NIKEName)
			if nikeScheme == nil {
				return fmt.Errorf("failed to resolve NIKE scheme: %s", geometry.NIKEName)
			}

			pubKey, err := nikepem.FromPublicPEMFile(publicKeyFile, nikeScheme)
			if err != nil {
				return fmt.Errorf("hop %d: failed to load NIKE key from %s: %v", i, publicKeyFile, err)
			}
			hop.NIKEPublicKey = pubKey
		} else if geometry.KEMName != "" {
			kemScheme := kemschemes.ByName(geometry.KEMName)
			if kemScheme == nil {
				return fmt.Errorf("failed to resolve KEM scheme: %s", geometry.KEMName)
			}

			pubKey, err := kempem.FromPublicPEMFile(publicKeyFile, kemScheme)
			if err != nil {
				return fmt.Errorf("hop %d: failed to load KEM key from %s: %v", i, publicKeyFile, err)
			}
			hop.KEMPublicKey = pubKey
		} else {
			return fmt.Errorf("geometry has neither NIKE nor KEM scheme")
		}

		// Add commands based on hop type
		if i < len(hops)-1 {
			// Non-terminal hop: no commands needed for this use case
		} else {
			// Terminal hop: add recipient command with blank (all zeros) recipient ID
			recipient := &commands.Recipient{}
			// recipient.ID is already initialized to all zeros
			hop.Commands = append(hop.Commands, recipient)
		}

		newPacket.Path[i] = hop
	}

	return nil
}

// generateSphinxPacket creates a new Sphinx packet
func generateSphinxPacket(newPacket *NewPacket) {
	// Validate required parameters
	if newPacket.GeometryFile == "" {
		log.Fatalf("geometry file is required (use -geometry flag)")
	}
	if len(newPacket.Path) == 0 {
		log.Fatalf("path is required (specify path hops as command line arguments)")
	}

	// Load geometry from TOML file
	geometry, err := loadGeometryFromTOML(newPacket.GeometryFile)
	if err != nil {
		log.Fatalf("failed to load geometry: %v", err)
	}

	// Create Sphinx instance from geometry
	sphinx, err := sphinx.FromGeometry(geometry)
	if err != nil {
		log.Fatalf("failed to create Sphinx instance: %v", err)
	}

	// Use the provided path
	path := newPacket.Path

	// Read payload
	var payload []byte
	if newPacket.PayloadFile == "" {
		// Read from stdin
		payload, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read payload from stdin: %v", err)
		}
	} else {
		// Read from file
		payload, err = os.ReadFile(newPacket.PayloadFile)
		if err != nil {
			log.Fatalf("failed to read payload file: %v", err)
		}
	}

	// Ensure payload is the correct size
	if len(payload) > geometry.ForwardPayloadLength {
		log.Fatalf("payload too large: %d bytes, max %d bytes", len(payload), geometry.ForwardPayloadLength)
	}

	// Pad payload to correct size
	if len(payload) < geometry.ForwardPayloadLength {
		paddedPayload := make([]byte, geometry.ForwardPayloadLength)
		copy(paddedPayload, payload)
		payload = paddedPayload
	}

	// Create the packet
	packet, err := sphinx.NewPacket(rand.Reader, path, payload)
	if err != nil {
		log.Fatalf("failed to create Sphinx packet: %v", err)
	}

	// Write packet to output
	if newPacket.OutputFile == "" {
		// Write to stdout
		_, err = os.Stdout.Write(packet)
		if err != nil {
			log.Fatalf("failed to write packet to stdout: %v", err)
		}
	} else {

		// Write to file
		err = os.WriteFile(newPacket.OutputFile, packet, 0644)
		if err != nil {
			log.Fatalf("failed to write packet to file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Sphinx packet written to %s (%d bytes)\n", newPacket.OutputFile, len(packet))
	}
}
