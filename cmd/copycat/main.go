// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// copycat - A CLI tool for reading and writing to Katzenpost pigeonhole channels
//
// Similar to cat or netcat, copycat can:
// - Read from stdin or a file and write to a copy stream (send mode)
// - Read from a channel and write to stdout (receive mode)
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/common"
	"github.com/spf13/cobra"
)

const (
	// chunkSize is the size of each chunk when streaming input data.
	// Using 10MB chunks to balance memory usage and RPC overhead.
	chunkSize = 10 * 1024 * 1024
)

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "copycat",
		Short: "Katzenpost pigeonhole copy stream tool",
		Long: `A CLI tool for reading and writing to Katzenpost pigeonhole channels.

Similar to cat or netcat, copycat can:
- Read from stdin or a file and write to a copy stream (send mode)
- Read from a channel and write to stdout (receive mode)

This tool uses the Pigeonhole protocol with Copy Commands to provide
reliable message delivery through the mixnet.`,
	}

	cmd.AddCommand(newSendCommand())
	cmd.AddCommand(newReceiveCommand())
	cmd.AddCommand(newGenKeyCommand())

	return cmd
}

// newGenKeyCommand creates the genkey subcommand
func newGenKeyCommand() *cobra.Command {
	var configFile string
	var thinClientOnly bool

	cmd := &cobra.Command{
		Use:   "genkey",
		Short: "Generate a new keypair and print both capabilities",
		Long: `Generate a new BACAP keypair and print both capabilities (base64 encoded).

The read capability can be shared with recipients to allow them to read messages.
The write capability must be kept secret and used with the send command.
The first index is used to specify the starting position for read/write operations.`,
		Example: `  # Generate a new keypair
  copycat genkey -c client.toml

  # Generate using thin client mode
  copycat genkey -c client.toml --thin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			thinClient, daemon := initializeClient(configFile, thinClientOnly)
			defer cleanup(daemon, thinClient)

			ctx := context.Background()

			// Generate a random seed
			seed := make([]byte, 32)
			if _, err := rand.Reader.Read(seed); err != nil {
				return fmt.Errorf("failed to generate seed: %w", err)
			}

			// Create keypair
			writeCap, readCap, firstIndex, err := thinClient.NewKeypair(ctx, seed)
			if err != nil {
				return fmt.Errorf("failed to create keypair: %w", err)
			}

			// Serialize and print capabilities
			readCapBytes, err := readCap.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed to marshal read capability: %w", err)
			}

			writeCapBytes, err := writeCap.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed to marshal write capability: %w", err)
			}

			firstIndexBytes, err := firstIndex.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed to marshal first index: %w", err)
			}

			fmt.Printf("Read Capability (share with recipient):\n%s\n\n", base64.StdEncoding.EncodeToString(readCapBytes))
			fmt.Printf("Write Capability (keep secret):\n%s\n\n", base64.StdEncoding.EncodeToString(writeCapBytes))
			fmt.Printf("First Index:\n%s\n", base64.StdEncoding.EncodeToString(firstIndexBytes))

			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "configuration file (required)")
	cmd.Flags().BoolVar(&thinClientOnly, "thin", false, "use thin client mode (connect to existing daemon)")
	cmd.MarkFlagRequired("config")

	return cmd
}

// newSendCommand creates the send subcommand
func newSendCommand() *cobra.Command {
	var configFile string
	var thinClientOnly bool
	var writeCapB64 string
	var inputFile string
	var startIndexB64 string
	var logLevel string

	cmd := &cobra.Command{
		Use:   "send",
		Short: "Read from stdin or file and write to a copy stream",
		Long: `Read data from stdin or a file and write it to a pigeonhole channel
using the Copy Command protocol.

The data is encrypted into CourierEnvelopes and written to a temporary
channel, then a Copy Command is sent to the courier to forward the
envelopes to the destination replicas.`,
		Example: `  # Send data from stdin
  echo "Hello, World!" | copycat send -c client.toml -w <write_cap>

  # Send data from a file
  copycat send -c client.toml -w <write_cap> -f message.txt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSend(configFile, thinClientOnly, writeCapB64, inputFile, startIndexB64, logLevel)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "configuration file (required)")
	cmd.Flags().BoolVar(&thinClientOnly, "thin", false, "use thin client mode")
	cmd.Flags().StringVarP(&writeCapB64, "write-cap", "w", "", "write capability (base64)")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "input file (default: stdin)")
	cmd.Flags().StringVarP(&startIndexB64, "index", "i", "", "start index (base64)")
	cmd.Flags().StringVar(&logLevel, "log-level", "ERROR", "logging level (DEBUG, INFO, NOTICE, WARNING, ERROR)")
	cmd.MarkFlagRequired("config")
	cmd.MarkFlagRequired("write-cap")

	return cmd
}

// newReceiveCommand creates the receive subcommand
func newReceiveCommand() *cobra.Command {
	var configFile string
	var thinClientOnly bool
	var readCapB64 string
	var startIndexB64 string
	var logLevel string

	cmd := &cobra.Command{
		Use:   "receive",
		Short: "Read from a channel and write to stdout",
		Long: `Read data from a pigeonhole channel and write it to stdout.

This command reads messages from the specified channel using the
read capability and writes the decrypted plaintext to stdout.

The data is expected to have a 4-byte big-endian length prefix.
The receiver will keep reading boxes (with retries) until all
data specified by the length prefix has been received.`,
		Example: `  # Receive data from a channel
  copycat receive -c client.toml -r <read_cap>

  # Receive from a specific starting index
  copycat receive -c client.toml -r <read_cap> -i <start_index>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReceive(configFile, thinClientOnly, readCapB64, startIndexB64, logLevel)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "configuration file (required)")
	cmd.Flags().BoolVar(&thinClientOnly, "thin", false, "use thin client mode")
	cmd.Flags().StringVarP(&readCapB64, "read-cap", "r", "", "read capability (base64)")
	cmd.Flags().StringVarP(&startIndexB64, "index", "i", "", "start index (base64)")
	cmd.Flags().StringVar(&logLevel, "log-level", "ERROR", "logging level (DEBUG, INFO, NOTICE, WARNING, ERROR)")
	cmd.MarkFlagRequired("config")
	cmd.MarkFlagRequired("read-cap")

	return cmd
}

// runSend reads from stdin or file and writes to a copy stream
func runSend(configFile string, thinClientOnly bool, writeCapB64, inputFile, startIndexB64 string, logLevel string) error {
	// Decode write capability
	writeCapBytes, err := base64.StdEncoding.DecodeString(writeCapB64)
	if err != nil {
		return fmt.Errorf("failed to decode write capability: %w", err)
	}
	writeCap, err := bacap.NewWriteCapFromBytes(writeCapBytes)
	if err != nil {
		return fmt.Errorf("failed to parse write capability: %w", err)
	}

	// Initialize client with logging configuration
	thinClient, daemon := initializeClientWithLogging(configFile, thinClientOnly, logLevel)
	defer cleanup(daemon, thinClient)

	ctx := context.Background()

	// Determine start index
	var startIndex *bacap.MessageBoxIndex
	if startIndexB64 != "" {
		indexBytes, err := base64.StdEncoding.DecodeString(startIndexB64)
		if err != nil {
			return fmt.Errorf("failed to decode start index: %w", err)
		}
		startIndex, err = bacap.NewEmptyMessageBoxIndexFromBytes(indexBytes)
		if err != nil {
			return fmt.Errorf("failed to parse start index: %w", err)
		}
	} else {
		startIndex = writeCap.GetFirstMessageBoxIndex()
	}

	// Read all input data first to determine total length for length prefixing
	var inputData []byte
	if inputFile != "" {
		var err error
		inputData, err = os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
	} else {
		var err error
		inputData, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
	}

	// Prepend 4-byte big-endian length prefix
	totalLen := uint32(len(inputData))
	lengthPrefix := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthPrefix, totalLen)
	prefixedData := append(lengthPrefix, inputData...)

	fmt.Fprintf(os.Stderr, "Sending %d bytes (with 4-byte length prefix)\n", len(inputData))

	// Create temporary copy stream channel
	seed := make([]byte, 32)
	if _, err := rand.Reader.Read(seed); err != nil {
		return fmt.Errorf("failed to generate seed: %w", err)
	}
	copyWriteCap, _, copyStartIndex, err := thinClient.NewKeypair(ctx, seed)
	if err != nil {
		return fmt.Errorf("failed to create copy stream keypair: %w", err)
	}

	// Generate stream ID
	streamID := thinClient.NewStreamID()

	// Stream prefixed data in chunks
	copyIndex := copyStartIndex
	chunkNum := 0
	offset := 0

	for offset < len(prefixedData) {
		// Determine chunk size
		remaining := len(prefixedData) - offset
		currentChunkSize := chunkSize
		if remaining < currentChunkSize {
			currentChunkSize = remaining
		}

		payload := prefixedData[offset : offset+currentChunkSize]
		isLast := offset+currentChunkSize >= len(prefixedData)

		// Create courier envelopes from this chunk
		chunks, err := thinClient.CreateCourierEnvelopesFromPayload(ctx, streamID, payload, writeCap, startIndex, isLast)
		if err != nil {
			return fmt.Errorf("failed to create courier envelopes for chunk %d: %w", chunkNum, err)
		}

		// Write each envelope to the copy stream
		for i, chunk := range chunks {
			ciphertext, envDesc, envHash, epoch, err := thinClient.EncryptWrite(ctx, chunk, copyWriteCap, copyIndex)
			if err != nil {
				return fmt.Errorf("failed to encrypt chunk %d envelope %d: %w", chunkNum, i, err)
			}

			// For write operations, nextMessageIndex and replyIndex are not used by the daemon
			// but the API still requires them. We pass nil/empty values.
			_, err = thinClient.StartResendingEncryptedMessage(ctx, nil, copyWriteCap, nil, nil, envDesc, ciphertext, envHash, epoch)
			if err != nil {
				return fmt.Errorf("failed to send chunk %d envelope %d: %w", chunkNum, i, err)
			}

			// Advance to next index using local BACAP computation (no RPC needed)
			copyIndex, err = copyIndex.NextIndex()
			if err != nil {
				return fmt.Errorf("failed to compute next index: %w", err)
			}
		}

		fmt.Fprintf(os.Stderr, "Processed chunk %d (%d bytes, %d envelopes)\n", chunkNum, currentChunkSize, len(chunks))
		chunkNum++
		offset += currentChunkSize
	}

	// Send Copy command to courier using ARQ for reliable delivery
	fmt.Fprintln(os.Stderr, "Sending Copy command to courier...")
	err = thinClient.StartResendingCopyCommand(ctx, copyWriteCap)
	if err != nil {
		return fmt.Errorf("copy command failed: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Copy command completed successfully")
	return nil
}

// runReceive reads from a channel and writes to stdout
// It expects a 4-byte big-endian length prefix followed by the actual data.
// Keeps reading and retrying until all data is received.
func runReceive(configFile string, thinClientOnly bool, readCapB64, startIndexB64 string, logLevel string) error {
	// Decode read capability
	readCapBytes, err := base64.StdEncoding.DecodeString(readCapB64)
	if err != nil {
		return fmt.Errorf("failed to decode read capability: %w", err)
	}
	readCap, err := bacap.ReadCapFromBytes(readCapBytes)
	if err != nil {
		return fmt.Errorf("failed to parse read capability: %w", err)
	}

	// Initialize client with logging configuration
	thinClient, daemon := initializeClientWithLogging(configFile, thinClientOnly, logLevel)
	defer cleanup(daemon, thinClient)

	ctx := context.Background()

	// Determine start index
	var currentIndex *bacap.MessageBoxIndex
	if startIndexB64 != "" {
		indexBytes, err := base64.StdEncoding.DecodeString(startIndexB64)
		if err != nil {
			return fmt.Errorf("failed to decode start index: %w", err)
		}
		currentIndex, err = bacap.NewEmptyMessageBoxIndexFromBytes(indexBytes)
		if err != nil {
			return fmt.Errorf("failed to parse start index: %w", err)
		}
	} else {
		currentIndex = readCap.GetFirstMessageBoxIndex()
	}

	fmt.Fprintln(os.Stderr, "Reading with length prefix...")

	// Buffer to accumulate all received data
	var receivedData []byte
	var expectedLen uint32
	lengthKnown := false
	boxNum := 0

	// Keep reading until we have all expected data
	for {
		// Try to read the next box with retries
		var plaintext []byte
		var readErr error
		const maxRetries = 100
		const baseDelay = 500 * time.Millisecond

		for attempt := 0; attempt < maxRetries; attempt++ {
			// Encrypt read request
			ciphertext, nextIndexBytes, envDesc, envHash, epoch, err := thinClient.EncryptRead(ctx, readCap, currentIndex)
			if err != nil {
				return fmt.Errorf("failed to encrypt read for box %d: %w", boxNum, err)
			}

			// Send and wait for reply
			var replyIndex uint8 = 0
			plaintext, readErr = thinClient.StartResendingEncryptedMessage(ctx, readCap, nil, nextIndexBytes, &replyIndex, envDesc, ciphertext, envHash, epoch)
			if readErr == nil && len(plaintext) > 0 {
				// Success
				break
			}

			// Box not found yet, retry with exponential backoff
			if attempt < maxRetries-1 {
				delay := baseDelay * time.Duration(1<<min(attempt, 6)) // Cap at ~32 seconds
				fmt.Fprintf(os.Stderr, "Box %d not ready (attempt %d/%d), retrying in %v...\n", boxNum, attempt+1, maxRetries, delay)
				time.Sleep(delay)
			}
		}

		if readErr != nil {
			return fmt.Errorf("failed to read box %d after %d retries: %w", boxNum, maxRetries, readErr)
		}

		if len(plaintext) == 0 {
			return fmt.Errorf("box %d is empty after %d retries", boxNum, maxRetries)
		}

		// Accumulate received data
		receivedData = append(receivedData, plaintext...)
		boxNum++

		// Check if we now know the expected length
		if !lengthKnown && len(receivedData) >= 4 {
			expectedLen = binary.BigEndian.Uint32(receivedData[:4])
			lengthKnown = true
			fmt.Fprintf(os.Stderr, "Expected payload length: %d bytes\n", expectedLen)
		}

		// Check if we have all the data (4-byte prefix + expectedLen bytes)
		if lengthKnown && uint32(len(receivedData)) >= 4+expectedLen {
			fmt.Fprintf(os.Stderr, "Received all %d bytes in %d boxes\n", expectedLen, boxNum)
			break
		}

		// Advance to next index
		currentIndex, err = currentIndex.NextIndex()
		if err != nil {
			return fmt.Errorf("failed to compute next index: %w", err)
		}
	}

	// Strip the 4-byte length prefix and write the actual payload to stdout
	if len(receivedData) < 4 {
		return fmt.Errorf("received data too short: %d bytes", len(receivedData))
	}
	payload := receivedData[4 : 4+expectedLen]
	_, err = os.Stdout.Write(payload)
	if err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Done")
	return nil
}
