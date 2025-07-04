// SPDX-FileCopyrightText: Copyright (C) 2025  David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikepem "github.com/katzenpost/hpqc/nike/pem"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// Flag name constants to avoid duplication
const (
	flagPrivateKey                = "private-key"
	flagOutputSURB                = "output-surb"
	flagOutputKeys                = "output-keys"
	flagOutputSURBKeys            = "output-surb-keys"
	flagGeometryConfigDescription = "path to TOML geometry config file (required)"
)

// Error message constants to avoid duplication
const (
	errFailedToLoadGeometry = "failed to load geometry: %v"
	errFailedToCreateSphinx = "failed to create Sphinx instance: %v"
	errFailedToResolveNIKE  = "failed to resolve NIKE scheme: %s"
	errFailedToResolveKEM   = "failed to resolve KEM scheme: %s"
	errGeometryNoScheme     = "geometry has neither NIKE nor KEM scheme"
	errFormat               = "Error: %v\n"
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

var rootCmd = &cobra.Command{
	Use:   "sphinx",
	Short: "Sphinx packet manipulation tool for mixnet communication",
	Long: `The Sphinx CLI tool implements the Sphinx packet format for anonymous communication
through mixnets. It provides complete functionality for creating forward packets,
reply mechanisms through SURBs (Single Use Reply Blocks), and packet processing.

Core capabilities:
• Create forward Sphinx packets with optional embedded SURBs for replies
• Generate standalone SURBs for reply mechanisms
• Unwrap and process packets at each "hop"
• Create reply packets from existing SURBs
• Decrypt SURB reply payloads using SURB keys
• Extract embedded SURBs from forward packets

The tool supports both NIKE (Non-Interactive Key Exchange) and KEM (Key Encapsulation
Mechanism) cryptographic schemes for post-quantum security. All operations require
a geometry configuration file that defines the cryptographic parameters and packet
structure for the target mixnet.`,
	Example: `  # Create a forward packet through two mix nodes
  sphinx newpacket --geometry config.toml \
    --hop "abc123...,node1_key.pem" \
    --hop "789abc...,node2_key.pem"

  # Create packet with embedded SURB for replies
  sphinx newpacket --geometry config.toml \
    --hop "abc123...,node1_key.pem" \
    --hop "789abc...,node2_key.pem" \
    --include-surb \
    --surb-hop "def456...,node3_key.pem" \
    --output-surb-keys reply.keys

  # Generate standalone SURB for replies
  sphinx newsurb --geometry config.toml \
    --hop "abc123...,node1_key.pem" \
    --hop "789abc...,node2_key.pem" \
    --output-surb reply.surb

  # Unwrap packet at mix node
  sphinx unwrap --geometry config.toml \
    --private-key node_private.pem \
    --packet incoming.bin`,
	SilenceErrors: true,
	SilenceUsage:  true,
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

		// Validate input parameters
		if err := validateCreateGeometryParams(&createGeometry); err != nil {
			fmt.Fprintf(os.Stderr, errFormat, err)
			os.Exit(1)
		}

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

Optionally embed a SURB for reply capability using --include-surb and --surb-hop flags.

Examples:
  # Simple forward packet
  sphinx newpacket --geometry config.toml \
    --hop "abc123...,node1_key.pem" \
    --hop "789abc...,node2_key.pem"

  # Forward packet with embedded SURB for replies
  sphinx newpacket --geometry config.toml \
    --hop "abc123...,node1_key.pem" \
    --hop "789abc...,node2_key.pem" \
    --include-surb \
    --surb-hop "def456...,node3_key.pem" \
    --surb-hop "ghi789...,node4_key.pem" \
    --output-surb-keys reply.keys`,
	Run: func(cmd *cobra.Command, args []string) {
		var newPacket NewPacket

		// Get flag values
		newPacket.GeometryFile, _ = cmd.Flags().GetString("geometry")
		newPacket.OutputFile, _ = cmd.Flags().GetString("output")
		newPacket.PayloadFile, _ = cmd.Flags().GetString("payload")
		hops, _ := cmd.Flags().GetStringArray("hop")

		// SURB-related flags
		includeSURB, _ := cmd.Flags().GetBool("include-surb")
		surbHops, _ := cmd.Flags().GetStringArray("surb-hop")
		outputSURBKeysFile, _ := cmd.Flags().GetString(flagOutputSURBKeys)

		// Build path from hop specifications
		err := buildPathFromHops(&newPacket, hops)
		if err != nil {
			fmt.Fprintf(os.Stderr, errFormat, err)
			os.Exit(1)
		}

		generateSphinxPacketWithOptionalSURB(&newPacket, includeSURB, surbHops, outputSURBKeysFile)
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

		// Validate that key file exists and is readable
		if err := validateFileExists(keyFile, "public key"); err != nil {
			fmt.Fprintf(os.Stderr, errFormat, err)
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
		privateKeyFile, _ := cmd.Flags().GetString(flagPrivateKey)
		packetFile, _ := cmd.Flags().GetString("packet")
		outputFile, _ := cmd.Flags().GetString("output")
		outputPacketFile, _ := cmd.Flags().GetString("output-packet")
		outputSURBFile, _ := cmd.Flags().GetString(flagOutputSURB)

		// Validate input files exist
		if err := validateFileExists(geometryFile, "geometry"); err != nil {
			fmt.Fprintf(os.Stderr, errFormat, err)
			os.Exit(1)
		}
		if err := validateFileExists(privateKeyFile, "private key"); err != nil {
			fmt.Fprintf(os.Stderr, errFormat, err)
			os.Exit(1)
		}
		if err := validateFileExists(packetFile, "packet"); err != nil {
			fmt.Fprintf(os.Stderr, errFormat, err)
			os.Exit(1)
		}

		unwrapSphinxPacket(geometryFile, privateKeyFile, packetFile, outputFile, outputPacketFile, outputSURBFile)
	},
}

var newSURBCmd = &cobra.Command{
	Use:   "newsurb",
	Short: "Create a new Sphinx SURB (Single Use Reply Block)",
	Long: `Create a new Sphinx SURB that can be used to send reply packets back through the mixnet.
A SURB contains the routing information and cryptographic keys needed for replies.

Example:
  sphinx newsurb --geometry config.toml \
    --hop "abc123...,node1_key.pem" \
    --hop "789abc...,node2_key.pem" \
    --output-surb reply.surb \
    --output-keys reply.keys`,
	Run: func(cmd *cobra.Command, args []string) {
		geometryFile, _ := cmd.Flags().GetString("geometry")
		outputSURBFile, _ := cmd.Flags().GetString(flagOutputSURB)
		outputKeysFile, _ := cmd.Flags().GetString(flagOutputKeys)
		hops, _ := cmd.Flags().GetStringArray("hop")

		generateSphinxSURB(geometryFile, hops, outputSURBFile, outputKeysFile)
	},
}

var newPacketFromSURBCmd = &cobra.Command{
	Use:   "newpacketfromsurb",
	Short: "Create a new Sphinx packet from a SURB",
	Long: `Create a new Sphinx reply packet using a SURB (Single Use Reply Block).
This creates a packet that will be routed back through the mixnet using the SURB's routing information.

Example:
  sphinx newpacketfromsurb --geometry config.toml \
    --surb reply.surb \
    --payload message.txt \
    --output reply_packet.bin`,
	Run: func(cmd *cobra.Command, args []string) {
		geometryFile, _ := cmd.Flags().GetString("geometry")
		surbFile, _ := cmd.Flags().GetString("surb")
		payloadFile, _ := cmd.Flags().GetString("payload")
		outputFile, _ := cmd.Flags().GetString("output")

		generateSphinxPacketFromSURB(geometryFile, surbFile, payloadFile, outputFile)
	},
}

var decryptSURBPayloadCmd = &cobra.Command{
	Use:   "decryptsurbpayload",
	Short: "Decrypt a SURB payload using SURB keys",
	Long: `Decrypt a SURB payload that was extracted from a reply packet using the SURB decryption keys.
This is the final step in the SURB workflow to recover the original plaintext.

Example:
  sphinx decryptsurbpayload --geometry config.toml \
    --keys reply.keys \
    --payload encrypted_payload.bin \
    --output decrypted_message.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		geometryFile, _ := cmd.Flags().GetString("geometry")
		keysFile, _ := cmd.Flags().GetString("keys")
		payloadFile, _ := cmd.Flags().GetString("payload")
		outputFile, _ := cmd.Flags().GetString("output")

		decryptSURBPayload(geometryFile, keysFile, payloadFile, outputFile)
	},
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(createGeometryCmd)
	rootCmd.AddCommand(newPacketCmd)
	rootCmd.AddCommand(genNodeIDCmd)
	rootCmd.AddCommand(unwrapCmd)
	rootCmd.AddCommand(newSURBCmd)
	rootCmd.AddCommand(newPacketFromSURBCmd)
	rootCmd.AddCommand(decryptSURBPayloadCmd)

	// createGeometry flags
	createGeometryCmd.Flags().Int("nrMixLayers", 3, "number of hops per route not counting ingress/egress nodes")
	createGeometryCmd.Flags().String("kem", "", "Name of the KEM Scheme to be used with Sphinx")
	createGeometryCmd.Flags().String("nike", "x25519", "Name of the NIKE Scheme to be used with Sphinx")
	createGeometryCmd.Flags().Int("UserForwardPayloadLength", 2000, "UserForwardPayloadLength")
	createGeometryCmd.Flags().String("file", "", "file path to write TOML output to, empty indicates stdout")

	// newpacket flags
	newPacketCmd.Flags().String("geometry", "", flagGeometryConfigDescription)
	newPacketCmd.Flags().String("output", "", "file to write the Sphinx packet to (default: stdout)")
	newPacketCmd.Flags().String("payload", "", "file to read payload from (default: stdin)")
	newPacketCmd.Flags().StringArray("hop", []string{}, "hop specification: node_id_hex,public_key_pem_file (can be specified multiple times)")
	newPacketCmd.Flags().Bool("include-surb", false, "embed a SURB in the packet payload for reply capability")
	newPacketCmd.Flags().StringArray("surb-hop", []string{}, "SURB hop specification: node_id_hex,public_key_pem_file (used with --include-surb)")
	newPacketCmd.Flags().String(flagOutputSURBKeys, "", "file to write SURB decryption keys to (used with --include-surb)")

	// genNodeID flags
	genNodeIDCmd.Flags().String("key", "", "path to public key PEM file (required)")

	// unwrap flags
	unwrapCmd.Flags().String("geometry", "", flagGeometryConfigDescription)
	unwrapCmd.Flags().String(flagPrivateKey, "", "path to private key PEM file (required)")
	unwrapCmd.Flags().String("packet", "", "path to Sphinx packet file (required)")
	unwrapCmd.Flags().String("output", "", "file to write unwrapped payload to (default: stdout)")
	unwrapCmd.Flags().String("output-packet", "", "file to write the processed packet to (for forwarding to next hop)")
	unwrapCmd.Flags().String(flagOutputSURB, "", "file to write extracted SURB to (if payload contains embedded SURB)")

	// newsurb flags
	newSURBCmd.Flags().String("geometry", "", flagGeometryConfigDescription)
	newSURBCmd.Flags().StringArray("hop", []string{}, "hop specification: node_id_hex,public_key_pem_file (can be specified multiple times)")
	newSURBCmd.Flags().String(flagOutputSURB, "", "file to write the SURB to (required)")
	newSURBCmd.Flags().String(flagOutputKeys, "", "file to write the SURB decryption keys to (required)")

	// newpacketfromsurb flags
	newPacketFromSURBCmd.Flags().String("geometry", "", flagGeometryConfigDescription)
	newPacketFromSURBCmd.Flags().String("surb", "", "path to SURB file (required)")
	newPacketFromSURBCmd.Flags().String("payload", "", "file to read payload from (default: stdin)")
	newPacketFromSURBCmd.Flags().String("output", "", "file to write the Sphinx packet to (default: stdout)")

	// decryptsurbpayload flags
	decryptSURBPayloadCmd.Flags().String("geometry", "", flagGeometryConfigDescription)
	decryptSURBPayloadCmd.Flags().String("keys", "", "path to SURB keys file (required)")
	decryptSURBPayloadCmd.Flags().String("payload", "", "file to read encrypted payload from (default: stdin)")
	decryptSURBPayloadCmd.Flags().String("output", "", "file to write decrypted payload to (default: stdout)")

	// Mark required flags
	newPacketCmd.MarkFlagRequired("geometry")
	newPacketCmd.MarkFlagRequired("hop")
	genNodeIDCmd.MarkFlagRequired("key")
	unwrapCmd.MarkFlagRequired("geometry")
	unwrapCmd.MarkFlagRequired(flagPrivateKey)
	unwrapCmd.MarkFlagRequired("packet")
	newSURBCmd.MarkFlagRequired("geometry")
	newSURBCmd.MarkFlagRequired("hop")
	newSURBCmd.MarkFlagRequired(flagOutputSURB)
	newSURBCmd.MarkFlagRequired(flagOutputKeys)
	newPacketFromSURBCmd.MarkFlagRequired("geometry")
	newPacketFromSURBCmd.MarkFlagRequired("surb")
	decryptSURBPayloadCmd.MarkFlagRequired("geometry")
	decryptSURBPayloadCmd.MarkFlagRequired("keys")
}

func main() {
	common.ExecuteWithFang(rootCmd)
}

func createGeometryFromNIKE(nikeName string, userForwardPayloadLength, nrHops int) *geo.Geometry {
	nikeScheme := schemes.ByName(nikeName)
	if nikeScheme == nil {
		log.Fatalf("failed to resolve nike scheme %s", nikeName)
	}
	return geo.GeometryFromUserForwardPayloadLength(
		nikeScheme,
		userForwardPayloadLength,
		true,
		nrHops,
	)
}

func createGeometryFromKEM(kemName string, userForwardPayloadLength, nrHops int) *geo.Geometry {
	kemScheme := kemschemes.ByName(kemName)
	if kemScheme == nil {
		log.Fatalf("failed to resolve kem scheme %s", kemName)
	}
	return geo.KEMGeometryFromUserForwardPayloadLength(
		kemScheme,
		userForwardPayloadLength,
		true,
		nrHops,
	)
}

func writeGeometryToFile(tomlOut, filename string) {
	out, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer func() {
		if syncErr := out.Sync(); syncErr != nil {
			panic(syncErr)
		}
		if closeErr := out.Close(); closeErr != nil {
			panic(closeErr)
		}
	}()

	writeCount, err := out.Write([]byte(tomlOut))
	if err != nil {
		panic(err)
	}
	if writeCount != len(tomlOut) {
		panic("partial write failure")
	}
}

// validateCreateGeometryParams validates parameters for createGeometry command
func validateCreateGeometryParams(createGeometry *CreateGeometry) error {
	if err := validateCryptoScheme(createGeometry); err != nil {
		return err
	}

	if err := validateMixHops(createGeometry.NrMixHops); err != nil {
		return err
	}

	if err := validatePayloadLength(createGeometry.UserForwardPayloadLength); err != nil {
		return err
	}

	if err := validateSchemes(createGeometry); err != nil {
		return err
	}

	if err := validateOutputFile(createGeometry.File); err != nil {
		return err
	}

	return nil
}

// validateCryptoScheme validates that either NIKE or KEM is specified, but not both
func validateCryptoScheme(createGeometry *CreateGeometry) error {
	if createGeometry.NIKE == "" && createGeometry.KEM == "" {
		return fmt.Errorf("either --nike or --kem must be specified")
	}
	if createGeometry.NIKE != "" && createGeometry.KEM != "" {
		return fmt.Errorf("cannot specify both --nike and --kem, choose one")
	}
	return nil
}

// validateMixHops validates the number of mix hops
func validateMixHops(nrMixHops int) error {
	if nrMixHops < 1 {
		return fmt.Errorf("number of mix layers must be at least 1, got %d", nrMixHops)
	}
	if nrMixHops > 10 {
		return fmt.Errorf("number of mix layers cannot exceed 10, got %d", nrMixHops)
	}
	return nil
}

// validatePayloadLength validates the user forward payload length
func validatePayloadLength(payloadLength int) error {
	if payloadLength < 1 {
		return fmt.Errorf("user forward payload length must be positive, got %d", payloadLength)
	}
	if payloadLength > 1024*1024 {
		return fmt.Errorf("user forward payload length too large (max 1MB), got %d", payloadLength)
	}
	return nil
}

// validateSchemes validates NIKE and KEM schemes if specified
func validateSchemes(createGeometry *CreateGeometry) error {
	if createGeometry.NIKE != "" {
		nikeScheme := schemes.ByName(createGeometry.NIKE)
		if nikeScheme == nil {
			return fmt.Errorf("unknown NIKE scheme: %s", createGeometry.NIKE)
		}
	}

	if createGeometry.KEM != "" {
		kemScheme := kemschemes.ByName(createGeometry.KEM)
		if kemScheme == nil {
			return fmt.Errorf("unknown KEM scheme: %s", createGeometry.KEM)
		}
	}

	return nil
}

// validateOutputFile validates the output file path if specified
func validateOutputFile(filePath string) error {
	if filePath == "" {
		return nil
	}

	// Check if directory exists and is writable
	dir := filepath.Dir(filePath)
	if dir != "." {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("output directory does not exist: %s", dir)
		}
	}

	// Check if file already exists and warn (but don't fail)
	if _, err := os.Stat(filePath); err == nil {
		fmt.Fprintf(os.Stderr, "Warning: output file %s already exists and will be overwritten\n", filePath)
	}

	return nil
}

// validateFileExists checks if a file exists and is readable
func validateFileExists(filePath, fileType string) error {
	if filePath == "" {
		return fmt.Errorf("%s file path cannot be empty", fileType)
	}

	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("%s file does not exist: %s", fileType, filePath)
	}
	if err != nil {
		return fmt.Errorf("error accessing %s file %s: %v", fileType, filePath, err)
	}

	if info.IsDir() {
		return fmt.Errorf("%s file path is a directory, not a file: %s", fileType, filePath)
	}

	// Try to open the file to check if it's readable
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("%s file is not readable: %s (%v)", fileType, filePath, err)
	}
	file.Close()

	return nil
}

func generateSphinxGeometry(createGeometry *CreateGeometry) {
	nrHops := createGeometry.NrMixHops + 2
	var sphinxGeometry *geo.Geometry

	if createGeometry.NIKE != "" {
		sphinxGeometry = createGeometryFromNIKE(createGeometry.NIKE, createGeometry.UserForwardPayloadLength, nrHops)
	}
	if createGeometry.KEM != "" {
		sphinxGeometry = createGeometryFromKEM(createGeometry.KEM, createGeometry.UserForwardPayloadLength, nrHops)
	}

	tomlOut := sphinxGeometry.Display()
	if createGeometry.File == "" {
		fmt.Println(tomlOut)
	} else {
		writeGeometryToFile(tomlOut, createGeometry.File)
	}
}

func loadPrivateKey(geometry *geo.Geometry, privateKeyFile string) interface{} {
	if geometry.NIKEName != "" {
		nikeScheme := schemes.ByName(geometry.NIKEName)
		if nikeScheme == nil {
			log.Fatalf(errFailedToResolveNIKE, geometry.NIKEName)
		}

		privKey, err := nikepem.FromPrivatePEMFile(privateKeyFile, nikeScheme)
		if err != nil {
			log.Fatalf("failed to load NIKE private key from %s: %v", privateKeyFile, err)
		}
		return privKey
	}

	if geometry.KEMName != "" {
		kemScheme := kemschemes.ByName(geometry.KEMName)
		if kemScheme == nil {
			log.Fatalf(errFailedToResolveKEM, geometry.KEMName)
		}

		privKey, err := kempem.FromPrivatePEMFile(privateKeyFile, kemScheme)
		if err != nil {
			log.Fatalf("failed to load KEM private key from %s: %v", privateKeyFile, err)
		}
		return privKey
	}

	log.Fatalf(errGeometryNoScheme)
	return nil
}

func processCommands(cmds []commands.RoutingCommand) (string, string) {
	var nextHopNodeID, recipientID string

	for i, cmd := range cmds {
		switch c := cmd.(type) {
		case *commands.NextNodeHop:
			nextHopNodeID = hex.EncodeToString(c.ID[:])
			fmt.Fprintf(os.Stderr, "  Command %d: NextNodeHop to %s\n", i, nextHopNodeID)
		case *commands.Recipient:
			recipientID = hex.EncodeToString(c.ID[:])
			fmt.Fprintf(os.Stderr, "  Command %d: Recipient %s\n", i, recipientID)
		case *commands.SURBReply:
			surbIDHex := hex.EncodeToString(c.ID[:])
			fmt.Fprintf(os.Stderr, "  Command %d: SURBReply %x\n", i, c.ID[:])
			fmt.Printf("SURB_ID: %s\n", surbIDHex)
		default:
			fmt.Fprintf(os.Stderr, "  Command %d: Unknown command type\n", i)
		}
	}

	return nextHopNodeID, recipientID
}

func writePayloadOutput(payload []byte, outputFile, outputSURBFile string, geometry *geo.Geometry) {
	if len(payload) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "Payload size: %d bytes\n", len(payload))

	finalPayload := payload
	if outputSURBFile != "" {
		extractedPayload, err := extractSURBFromPayload(payload, outputSURBFile, geometry)
		if err != nil {
			log.Fatalf("failed to extract SURB: %v", err)
		}
		finalPayload = extractedPayload
	}

	if outputFile == "" {
		_, err := os.Stdout.Write(finalPayload)
		if err != nil {
			log.Fatalf("failed to write payload to stdout: %v", err)
		}
	} else {
		err := os.WriteFile(outputFile, finalPayload, 0644)
		if err != nil {
			log.Fatalf("failed to write payload to file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Payload written to %s\n", outputFile)
	}
}

// unwrapSphinxPacket unwraps a Sphinx packet using a private key
func unwrapSphinxPacket(geometryFile, privateKeyFile, packetFile, outputFile, outputPacketFile, outputSURBFile string) {
	geometry, err := loadGeometryFromTOML(geometryFile)
	if err != nil {
		log.Fatalf(errFailedToLoadGeometry, err)
	}

	sphinxInstance, err := sphinx.FromGeometry(geometry)
	if err != nil {
		log.Fatalf(errFailedToCreateSphinx, err)
	}

	privateKey := loadPrivateKey(geometry, privateKeyFile)

	packet, err := os.ReadFile(packetFile)
	if err != nil {
		log.Fatalf("failed to read packet file %s: %v", packetFile, err)
	}

	payload, replayTag, cmds, err := sphinxInstance.Unwrap(privateKey, packet)
	if err != nil {
		log.Fatalf("failed to unwrap Sphinx packet: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Packet unwrapped successfully!\n")
	fmt.Fprintf(os.Stderr, "Replay tag: %x\n", replayTag)
	fmt.Fprintf(os.Stderr, "Commands found: %d\n", len(cmds))

	nextHopNodeID, recipientID := processCommands(cmds)

	if nextHopNodeID != "" {
		fmt.Fprintf(os.Stderr, "\nNext hop node ID: %s\n", nextHopNodeID)
	} else {
		fmt.Fprintf(os.Stderr, "\nThis is the final hop (no next hop)\n")
	}

	if recipientID != "" {
		fmt.Fprintf(os.Stderr, "Recipient ID: %s\n", recipientID)
	}

	writePayloadOutput(payload, outputFile, outputSURBFile, geometry)

	if outputPacketFile != "" {
		err = os.WriteFile(outputPacketFile, packet, 0644)
		if err != nil {
			log.Fatalf("failed to write processed packet to file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Processed packet written to %s (%d bytes)\n", outputPacketFile, len(packet))
	}
}

// generateSphinxSURB creates a Sphinx SURB from the given parameters
func generateSphinxSURB(geometryFile string, hops []string, outputSURBFile, outputKeysFile string) {
	// Load geometry from TOML file
	geometry, err := loadGeometryFromTOML(geometryFile)
	if err != nil {
		log.Fatalf(errFailedToLoadGeometry, err)
	}

	// Create Sphinx instance from geometry
	sphinxInstance, err := sphinx.FromGeometry(geometry)
	if err != nil {
		log.Fatalf(errFailedToCreateSphinx, err)
	}

	// Validate hop count
	if len(hops) != geometry.NrHops {
		log.Fatalf("SURB paths require exactly %d hops for this geometry, got %d", geometry.NrHops, len(hops))
	}

	// Create the SURB path and call NewSURB directly
	path, surbID, err := createSURBPath(geometry, hops)
	if err != nil {
		log.Fatalf("failed to create SURB path: %v", err)
	}

	// Create the SURB
	surb, surbKeys, err := sphinxInstance.NewSURB(rand.Reader, path)
	if err != nil {
		log.Fatalf("failed to create SURB: %v", err)
	}

	// Extract first hop ID from the path
	firstHopID := hex.EncodeToString(path[0].ID[:])

	// Write SURB to file
	err = os.WriteFile(outputSURBFile, surb, 0644)
	if err != nil {
		log.Fatalf("failed to write SURB to file: %v", err)
	}

	// Save SURB keys with SURB ID
	err = saveSURBKeysWithIDs(outputKeysFile, surbKeys, surbID)
	if err != nil {
		log.Fatalf("failed to write SURB keys to file: %v", err)
	}

	fmt.Fprintf(os.Stderr, "SURB created successfully!\n")
	fmt.Fprintf(os.Stderr, "SURB written to %s (%d bytes)\n", outputSURBFile, len(surb))
	fmt.Fprintf(os.Stderr, "SURB keys written to %s (%d bytes)\n", outputKeysFile, len(surbKeys))
	fmt.Fprintf(os.Stderr, "\nTo use this SURB, share these components:\n")
	fmt.Fprintf(os.Stderr, "  SURB file: %s\n", outputSURBFile)
	fmt.Fprintf(os.Stderr, "  First hop ID: %s\n", firstHopID)
	fmt.Fprintf(os.Stderr, "\nKeep private:\n")
	fmt.Fprintf(os.Stderr, "  Decryption keys: %s\n", outputKeysFile)
}

func readPayloadFromSource(payloadFile string) []byte {
	var payload []byte
	var err error

	if payloadFile == "" {
		payload, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read payload from stdin: %v", err)
		}
	} else {
		payload, err = os.ReadFile(payloadFile)
		if err != nil {
			log.Fatalf("failed to read payload file: %v", err)
		}
	}

	return payload
}

func validateAndPadPayload(payload []byte, maxLength int) []byte {
	if len(payload) > maxLength {
		log.Fatalf("payload too large: %d bytes, max %d bytes", len(payload), maxLength)
	}

	if len(payload) < maxLength {
		paddedPayload := make([]byte, maxLength)
		copy(paddedPayload, payload)
		return paddedPayload
	}

	return payload
}

func writePacketOutput(packet []byte, outputFile string, firstHop *[32]byte) {
	fmt.Fprintf(os.Stderr, "Packet created from SURB successfully!\n")
	fmt.Fprintf(os.Stderr, "First hop node ID: %x\n", firstHop[:])
	fmt.Fprintf(os.Stderr, "Packet size: %d bytes\n", len(packet))

	var err error
	if outputFile == "" {
		_, err = os.Stdout.Write(packet)
		if err != nil {
			log.Fatalf("failed to write packet to stdout: %v", err)
		}
	} else {
		err = os.WriteFile(outputFile, packet, 0644)
		if err != nil {
			log.Fatalf("failed to write packet to file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Packet written to %s\n", outputFile)
	}
}

// generateSphinxPacketFromSURB creates a Sphinx packet from a SURB and payload
func generateSphinxPacketFromSURB(geometryFile, surbFile, payloadFile, outputFile string) {
	geometry, err := loadGeometryFromTOML(geometryFile)
	if err != nil {
		log.Fatalf(errFailedToLoadGeometry, err)
	}

	sphinxInstance, err := sphinx.FromGeometry(geometry)
	if err != nil {
		log.Fatalf(errFailedToCreateSphinx, err)
	}

	surb, err := os.ReadFile(surbFile)
	if err != nil {
		log.Fatalf("failed to read SURB file %s: %v", surbFile, err)
	}

	if len(surb) != geometry.SURBLength {
		log.Fatalf("invalid SURB length: got %d bytes, expected %d bytes", len(surb), geometry.SURBLength)
	}

	payload := readPayloadFromSource(payloadFile)
	payload = validateAndPadPayload(payload, geometry.ForwardPayloadLength)

	packet, firstHop, err := sphinxInstance.NewPacketFromSURB(surb, payload)
	if err != nil {
		log.Fatalf("failed to create packet from SURB: %v", err)
	}

	writePacketOutput(packet, outputFile, firstHop)
}

func readEncryptedPayload(payloadFile string) []byte {
	var encryptedPayload []byte
	var err error

	if payloadFile == "" {
		encryptedPayload, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read encrypted payload from stdin: %v", err)
		}
	} else {
		encryptedPayload, err = os.ReadFile(payloadFile)
		if err != nil {
			log.Fatalf("failed to read encrypted payload file: %v", err)
		}
	}

	return encryptedPayload
}

func writeDecryptedOutput(decryptedPayload []byte, outputFile string) {
	fmt.Fprintf(os.Stderr, "SURB payload decrypted successfully!\n")
	fmt.Fprintf(os.Stderr, "Decrypted payload size: %d bytes\n", len(decryptedPayload))

	var err error
	if outputFile == "" {
		_, err = os.Stdout.Write(decryptedPayload)
		if err != nil {
			log.Fatalf("failed to write decrypted payload to stdout: %v", err)
		}
	} else {
		err = os.WriteFile(outputFile, decryptedPayload, 0644)
		if err != nil {
			log.Fatalf("failed to write decrypted payload to file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Decrypted payload written to %s\n", outputFile)
	}
}

// decryptSURBPayload decrypts a SURB payload using SURB keys
func decryptSURBPayload(geometryFile, keysFile, payloadFile, outputFile string) {
	geometry, err := loadGeometryFromTOML(geometryFile)
	if err != nil {
		log.Fatalf(errFailedToLoadGeometry, err)
	}

	sphinxInstance, err := sphinx.FromGeometry(geometry)
	if err != nil {
		log.Fatalf(errFailedToCreateSphinx, err)
	}

	surbKeys, err := loadSURBKeysFromTOML(keysFile)
	if err != nil {
		log.Fatalf("failed to read SURB keys file %s: %v", keysFile, err)
	}

	encryptedPayload := readEncryptedPayload(payloadFile)

	decryptedPayload, err := sphinxInstance.DecryptSURBPayload(encryptedPayload, surbKeys)
	if err != nil {
		log.Fatalf("failed to decrypt SURB payload: %v", err)
	}

	writeDecryptedOutput(decryptedPayload, outputFile)
}

// generateNodeID creates a deterministic node ID from a public key file
func generateNodeID(keyFile string) {
	// Read the PEM file
	pemData, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("failed to read key file %s: %v", keyFile, err)
	}

	// Generate a deterministic node ID by hashing the PEM data
	hashResult := hash.Sum256(pemData)
	nodeID := hex.EncodeToString(hashResult[:])

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

func parseHopSpec(hopSpec string, hopIndex int) (string, string, error) {
	parts := strings.Split(hopSpec, ",")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("hop %d: expected format 'node_id_hex,public_key_pem_file', got %d parts", hopIndex, len(parts))
	}

	nodeID := strings.TrimSpace(parts[0])
	publicKeyFile := strings.TrimSpace(parts[1])
	return nodeID, publicKeyFile, nil
}

func parseNodeID(nodeID string, hopIndex int) ([32]byte, error) {
	var nodeIDArray [32]byte

	nodeIDBytes, err := hex.DecodeString(nodeID)
	if err != nil {
		return nodeIDArray, fmt.Errorf("hop %d: invalid node ID: %v", hopIndex, err)
	}
	if len(nodeIDBytes) != constants.NodeIDLength {
		return nodeIDArray, fmt.Errorf("hop %d: node ID has wrong length: got %d, expected %d", hopIndex, len(nodeIDBytes), constants.NodeIDLength)
	}

	// Validate that node ID bytes are non-zero
	allZero := true
	for _, b := range nodeIDBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nodeIDArray, fmt.Errorf("hop %d: node ID cannot be all zeros", hopIndex)
	}

	copy(nodeIDArray[:], nodeIDBytes)
	return nodeIDArray, nil
}

func loadHopPublicKey(geometry *geo.Geometry, publicKeyFile string, hopIndex int, hop *sphinx.PathHop) error {
	if geometry.NIKEName != "" {
		nikeScheme := schemes.ByName(geometry.NIKEName)
		if nikeScheme == nil {
			return fmt.Errorf(errFailedToResolveNIKE, geometry.NIKEName)
		}

		pubKey, err := nikepem.FromPublicPEMFile(publicKeyFile, nikeScheme)
		if err != nil {
			return fmt.Errorf("hop %d: failed to load NIKE key from %s: %v", hopIndex, publicKeyFile, err)
		}
		hop.NIKEPublicKey = pubKey
		return nil
	}

	if geometry.KEMName != "" {
		kemScheme := kemschemes.ByName(geometry.KEMName)
		if kemScheme == nil {
			return fmt.Errorf(errFailedToResolveKEM, geometry.KEMName)
		}

		pubKey, err := kempem.FromPublicPEMFile(publicKeyFile, kemScheme)
		if err != nil {
			return fmt.Errorf("hop %d: failed to load KEM key from %s: %v", hopIndex, publicKeyFile, err)
		}
		hop.KEMPublicKey = pubKey
		return nil
	}

	return fmt.Errorf(errGeometryNoScheme)
}

func createPathHop(geometry *geo.Geometry, hopSpec string, hopIndex int, isTerminal bool) (*sphinx.PathHop, error) {
	nodeID, publicKeyFile, err := parseHopSpec(hopSpec, hopIndex)
	if err != nil {
		return nil, err
	}

	nodeIDArray, err := parseNodeID(nodeID, hopIndex)
	if err != nil {
		return nil, err
	}

	hop := &sphinx.PathHop{}
	hop.ID = nodeIDArray

	err = loadHopPublicKey(geometry, publicKeyFile, hopIndex, hop)
	if err != nil {
		return nil, err
	}

	if isTerminal {
		recipient := &commands.Recipient{}
		hop.Commands = append(hop.Commands, recipient)
	}

	return hop, nil
}

// buildPathFromHops builds the Sphinx path from hop specifications
func buildPathFromHops(newPacket *NewPacket, hops []string) error {
	if len(hops) == 0 {
		return fmt.Errorf("no hops specified")
	}

	geometry, err := loadGeometryFromTOML(newPacket.GeometryFile)
	if err != nil {
		return fmt.Errorf(errFailedToLoadGeometry, err)
	}

	if len(hops) != geometry.NrHops {
		return fmt.Errorf("sphinx paths require exactly %d hops for this geometry, got %d", geometry.NrHops, len(hops))
	}

	newPacket.Path = make([]*sphinx.PathHop, len(hops))

	for i, hopSpec := range hops {
		isTerminal := i == len(hops)-1
		hop, err := createPathHop(geometry, hopSpec, i, isTerminal)
		if err != nil {
			return err
		}
		newPacket.Path[i] = hop
	}

	return nil
}

func validatePacketParameters(newPacket *NewPacket, includeSURB bool, surbHops []string, outputSURBKeysFile string) {
	if newPacket.GeometryFile == "" {
		log.Fatalf("geometry file is required (use -geometry flag)")
	}
	if len(newPacket.Path) == 0 {
		log.Fatalf("path is required (specify path hops as command line arguments)")
	}

	if includeSURB {
		if len(surbHops) == 0 {
			log.Fatalf("--surb-hop flags are required when using --include-surb")
		}
		if outputSURBKeysFile == "" {
			log.Fatalf("--%s is required when using --include-surb", flagOutputSURBKeys)
		}
	}
}

func createEmbeddedSURB(geometry *geo.Geometry, sphinxInstance *sphinx.Sphinx, surbHops []string, outputSURBKeysFile string, originalPayload []byte) []byte {
	surbPath, surbID, err := createSURBPath(geometry, surbHops)
	if err != nil {
		log.Fatalf("failed to create SURB path: %v", err)
	}

	surb, surbKeys, err := sphinxInstance.NewSURB(rand.Reader, surbPath)
	if err != nil {
		log.Fatalf("failed to create SURB: %v", err)
	}

	err = saveSURBKeysWithIDs(outputSURBKeysFile, surbKeys, surbID)
	if err != nil {
		log.Fatalf("failed to write SURB keys to file: %v", err)
	}

	finalPayload := combinePayloadWithSURB(originalPayload, surb, geometry.ForwardPayloadLength)

	fmt.Fprintf(os.Stderr, "SURB embedded in packet payload\n")
	fmt.Fprintf(os.Stderr, "SURB keys written to %s (%d bytes)\n", outputSURBKeysFile, len(surbKeys))

	return finalPayload
}

func writeSphinxPacket(packet []byte, outputFile string) {
	var err error
	if outputFile == "" {
		_, err = os.Stdout.Write(packet)
		if err != nil {
			log.Fatalf("failed to write packet to stdout: %v", err)
		}
	} else {
		err = os.WriteFile(outputFile, packet, 0644)
		if err != nil {
			log.Fatalf("failed to write packet to file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Sphinx packet written to %s (%d bytes)\n", outputFile, len(packet))
	}
}

// generateSphinxPacketWithOptionalSURB creates a new Sphinx packet with optional embedded SURB
func generateSphinxPacketWithOptionalSURB(newPacket *NewPacket, includeSURB bool, surbHops []string, outputSURBKeysFile string) {
	validatePacketParameters(newPacket, includeSURB, surbHops, outputSURBKeysFile)

	geometry, err := loadGeometryFromTOML(newPacket.GeometryFile)
	if err != nil {
		log.Fatalf(errFailedToLoadGeometry, err)
	}

	sphinxInstance, err := sphinx.FromGeometry(geometry)
	if err != nil {
		log.Fatalf(errFailedToCreateSphinx, err)
	}

	originalPayload := readPayloadFromSource(newPacket.PayloadFile)

	var finalPayload []byte
	if includeSURB {
		finalPayload = createEmbeddedSURB(geometry, sphinxInstance, surbHops, outputSURBKeysFile, originalPayload)
	} else {
		finalPayload = originalPayload
	}

	finalPayload = validateAndPadPayload(finalPayload, geometry.ForwardPayloadLength)

	packet, err := sphinxInstance.NewPacket(rand.Reader, newPacket.Path, finalPayload)
	if err != nil {
		log.Fatalf("failed to create Sphinx packet: %v", err)
	}

	writeSphinxPacket(packet, newPacket.OutputFile)
}

func generateSURBID() ([16]byte, error) {
	var surbID [16]byte
	_, err := rand.Read(surbID[:])
	if err != nil {
		return [16]byte{}, fmt.Errorf("failed to generate SURB ID: %v", err)
	}
	return surbID, nil
}

func determineCryptoSchemes(geometry *geo.Geometry) (nike.Scheme, kem.Scheme, error) {
	if geometry.NIKEName != "" {
		nikeScheme := schemes.ByName(geometry.NIKEName)
		if nikeScheme == nil {
			return nil, nil, fmt.Errorf(errFailedToResolveNIKE, geometry.NIKEName)
		}
		return nikeScheme, nil, nil
	}

	if geometry.KEMName != "" {
		kemScheme := kemschemes.ByName(geometry.KEMName)
		if kemScheme == nil {
			return nil, nil, fmt.Errorf(errFailedToResolveKEM, geometry.KEMName)
		}
		return nil, kemScheme, nil
	}

	return nil, nil, fmt.Errorf(errGeometryNoScheme)
}

func createSURBHop(hopSpec string, hopIndex int, surbID [16]byte, nikeScheme nike.Scheme, kemScheme kem.Scheme) (*sphinx.PathHop, error) {
	nodeID, publicKeyFile, err := parseHopSpec(hopSpec, hopIndex)
	if err != nil {
		return nil, err
	}

	nodeIDBytes, err := hex.DecodeString(nodeID)
	if err != nil {
		return nil, fmt.Errorf("SURB hop %d: invalid node ID: %v", hopIndex, err)
	}
	if len(nodeIDBytes) != constants.NodeIDLength {
		return nil, fmt.Errorf("SURB hop %d: node ID has wrong length: got %d, expected %d", hopIndex, len(nodeIDBytes), constants.NodeIDLength)
	}

	// Validate that node ID bytes are non-zero
	allZero := true
	for _, b := range nodeIDBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, fmt.Errorf("SURB hop %d: node ID cannot be all zeros", hopIndex)
	}

	hop := &sphinx.PathHop{}
	copy(hop.ID[:], nodeIDBytes)

	if nikeScheme != nil {
		pubKey, err := nikepem.FromPublicPEMFile(publicKeyFile, nikeScheme)
		if err != nil {
			return nil, fmt.Errorf("SURB hop %d: failed to load NIKE public key from %s: %v", hopIndex, publicKeyFile, err)
		}
		hop.NIKEPublicKey = pubKey
	} else {
		pubKey, err := kempem.FromPublicPEMFile(publicKeyFile, kemScheme)
		if err != nil {
			return nil, fmt.Errorf("SURB hop %d: failed to load KEM public key from %s: %v", hopIndex, publicKeyFile, err)
		}
		hop.KEMPublicKey = pubKey
	}

	surbReply := &commands.SURBReply{}
	copy(surbReply.ID[:], surbID[:])
	hop.Commands = append(hop.Commands, surbReply)

	return hop, nil
}

// createSURBPath creates a SURB path from hop specifications
func createSURBPath(geometry *geo.Geometry, surbHops []string) ([]*sphinx.PathHop, [16]byte, error) {
	if len(surbHops) != geometry.NrHops {
		return nil, [16]byte{}, fmt.Errorf("SURB paths require exactly %d hops for this geometry, got %d", geometry.NrHops, len(surbHops))
	}

	surbID, err := generateSURBID()
	if err != nil {
		return nil, [16]byte{}, err
	}

	nikeScheme, kemScheme, err := determineCryptoSchemes(geometry)
	if err != nil {
		return nil, [16]byte{}, err
	}

	path := make([]*sphinx.PathHop, len(surbHops))
	for i, hopSpec := range surbHops {
		hop, err := createSURBHop(hopSpec, i, surbID, nikeScheme, kemScheme)
		if err != nil {
			return nil, [16]byte{}, err
		}
		path[i] = hop
	}

	return path, surbID, nil
}

// combinePayloadWithSURB combines the original payload with a SURB using Sphinx format
func combinePayloadWithSURB(originalPayload, surb []byte, maxPayloadLength int) []byte {
	// Sphinx payload format: [1 byte flags][1 byte reserved][SURB if present][user payload]
	const (
		flagsSURB    = 1
		reserved     = 0
		headerLength = 2
	)

	// Calculate total size needed
	totalSize := headerLength + len(surb) + len(originalPayload)

	if totalSize > maxPayloadLength {
		log.Fatalf("combined payload and SURB too large: %d bytes, max %d bytes", totalSize, maxPayloadLength)
	}

	// Create combined payload with proper padding
	combined := make([]byte, maxPayloadLength)
	offset := 0

	// Write flags byte (1 = SURB present)
	combined[offset] = flagsSURB
	offset++

	// Write reserved byte (always 0)
	combined[offset] = reserved
	offset++

	// Write SURB
	copy(combined[offset:], surb)
	offset += len(surb)

	// Write original payload
	copy(combined[offset:], originalPayload)

	return combined
}

// saveSURBKeysWithIDs saves SURB keys with SURB ID in TOML format
func saveSURBKeysWithIDs(filename string, surbKeys []byte, surbID [16]byte) error {
	// Create TOML content with SURB ID and keys
	var content strings.Builder

	content.WriteString("# SURB Keys File\n")
	content.WriteString("# Generated by Sphinx CLI tool\n\n")

	// Write SURB ID
	content.WriteString(fmt.Sprintf("surb_id = \"%x\"\n\n", surbID[:]))

	// Write keys as base64
	keysBase64 := base64.StdEncoding.EncodeToString(surbKeys)
	content.WriteString(fmt.Sprintf("key_data = \"%s\"\n", keysBase64))

	// Write to file
	err := os.WriteFile(filename, []byte(content.String()), 0644)
	if err != nil {
		return err
	}

	// Also print SURB ID to stderr for visibility
	fmt.Fprintf(os.Stderr, "SURB ID created: %x\n", surbID[:])

	return nil
}

// SURBKeysFile represents the TOML structure for SURB keys
type SURBKeysFile struct {
	SURBID  string `toml:"surb_id"`
	KeyData string `toml:"key_data"`
}

// loadSURBKeysFromTOML loads SURB keys from a TOML file
func loadSURBKeysFromTOML(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read SURB keys file: %w", err)
	}

	var keysFile SURBKeysFile
	err = toml.Unmarshal(data, &keysFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TOML: %w", err)
	}

	// Decode base64 key data
	surbKeys, err := base64.StdEncoding.DecodeString(keysFile.KeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key data: %w", err)
	}

	return surbKeys, nil
}

// extractSURBFromPayload extracts a SURB from a combined payload and returns the remaining user payload
func extractSURBFromPayload(payload []byte, outputSURBFile string, geometry *geo.Geometry) ([]byte, error) {
	// Sphinx payload format: [1 byte flags][1 byte reserved][SURB if present][user payload]
	const (
		flagsSURB    = 1
		headerLength = 2
	)

	if len(payload) < headerLength {
		return payload, fmt.Errorf("payload too short to contain header")
	}

	// Check flags byte
	flags := payload[0]
	if flags != flagsSURB {
		// No SURB present, return original payload
		fmt.Fprintf(os.Stderr, "No SURB found in payload (flags=%d)\n", flags)
		return payload, nil
	}

	// SURB is present, extract it
	surbLength := geometry.SURBLength
	if len(payload) < headerLength+surbLength {
		return payload, fmt.Errorf("payload too short to contain SURB: need %d bytes, got %d", headerLength+surbLength, len(payload))
	}

	// Extract SURB blob
	surbStart := headerLength
	surbEnd := surbStart + surbLength
	surbBlob := payload[surbStart:surbEnd]

	// Write SURB to file
	err := os.WriteFile(outputSURBFile, surbBlob, 0644)
	if err != nil {
		return payload, fmt.Errorf("failed to write SURB to file: %v", err)
	}

	// Extract remaining user payload
	userPayload := payload[surbEnd:]

	fmt.Fprintf(os.Stderr, "SURB extracted successfully!\n")
	fmt.Fprintf(os.Stderr, "SURB written to %s (%d bytes)\n", outputSURBFile, len(surbBlob))
	fmt.Fprintf(os.Stderr, "User payload size: %d bytes\n", len(userPayload))

	return userPayload, nil
}
