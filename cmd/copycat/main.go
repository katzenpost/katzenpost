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
	defaultTimeoutSeconds = 120
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

			timeout := time.Duration(defaultTimeoutSeconds) * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

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
	var timeoutSeconds int
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
  copycat send -c client.toml -w <write_cap> -f message.txt

  # Send with custom timeout (10 minutes)
  copycat send -c client.toml -w <write_cap> --timeout 600`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSend(configFile, thinClientOnly, writeCapB64, inputFile, startIndexB64, timeoutSeconds, logLevel)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "configuration file (required)")
	cmd.Flags().BoolVar(&thinClientOnly, "thin", false, "use thin client mode")
	cmd.Flags().StringVarP(&writeCapB64, "write-cap", "w", "", "write capability (base64)")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "input file (default: stdin)")
	cmd.Flags().StringVarP(&startIndexB64, "index", "i", "", "start index (base64)")
	cmd.Flags().IntVar(&timeoutSeconds, "timeout", defaultTimeoutSeconds, "overall operation timeout in seconds")
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
	var count int
	var timeoutSeconds int
	var logLevel string

	cmd := &cobra.Command{
		Use:   "receive",
		Short: "Read from a channel and write to stdout",
		Long: `Read data from a pigeonhole channel and write it to stdout.

This command reads messages from the specified channel using the
read capability and writes the decrypted plaintext to stdout.`,
		Example: `  # Receive a single message
  copycat receive -c client.toml -r <read_cap>

  # Receive multiple messages
  copycat receive -c client.toml -r <read_cap> -n 5

  # Receive with custom timeout
  copycat receive -c client.toml -r <read_cap> --timeout 300`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReceive(configFile, thinClientOnly, readCapB64, startIndexB64, count, timeoutSeconds, logLevel)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "configuration file (required)")
	cmd.Flags().BoolVar(&thinClientOnly, "thin", false, "use thin client mode")
	cmd.Flags().StringVarP(&readCapB64, "read-cap", "r", "", "read capability (base64)")
	cmd.Flags().StringVarP(&startIndexB64, "index", "i", "", "start index (base64)")
	cmd.Flags().IntVarP(&count, "count", "n", 1, "number of messages to receive")
	cmd.Flags().IntVar(&timeoutSeconds, "timeout", defaultTimeoutSeconds, "overall operation timeout in seconds")
	cmd.Flags().StringVar(&logLevel, "log-level", "ERROR", "logging level (DEBUG, INFO, NOTICE, WARNING, ERROR)")
	cmd.MarkFlagRequired("config")
	cmd.MarkFlagRequired("read-cap")

	return cmd
}

// runSend reads from stdin or file and writes to a copy stream
func runSend(configFile string, thinClientOnly bool, writeCapB64, inputFile, startIndexB64 string, timeoutSeconds int, logLevel string) error {
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

	timeout := time.Duration(timeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

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

	// Read input data
	var input io.Reader
	if inputFile != "" {
		f, err := os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer f.Close()
		input = f
	} else {
		input = os.Stdin
	}

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

	// Stream input in chunks to avoid loading entire file into RAM
	copyIndex := copyStartIndex
	chunkNum := 0
	buf := make([]byte, chunkSize)

	for {
		n, readErr := io.ReadFull(input, buf)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read input: %w", readErr)
		}

		// Determine if this is the last chunk
		isLast := readErr == io.EOF || readErr == io.ErrUnexpectedEOF

		// Skip empty final reads
		if n == 0 && isLast {
			break
		}

		payload := buf[:n]

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

		fmt.Fprintf(os.Stderr, "Processed chunk %d (%d bytes, %d envelopes)\n", chunkNum, n, len(chunks))
		chunkNum++

		if isLast {
			break
		}
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
func runReceive(configFile string, thinClientOnly bool, readCapB64, startIndexB64 string, count int, timeoutSeconds int, logLevel string) error {
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

	timeout := time.Duration(timeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

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

	fmt.Fprintf(os.Stderr, "Reading %d message(s)...\n", count)

	// Read messages
	for i := 0; i < count; i++ {
		// Encrypt read request
		ciphertext, nextIndexBytes, envDesc, envHash, epoch, err := thinClient.EncryptRead(ctx, readCap, currentIndex)
		if err != nil {
			return fmt.Errorf("failed to encrypt read %d: %w", i, err)
		}

		// Send and wait for reply
		var replyIndex uint8 = 0
		plaintext, err := thinClient.StartResendingEncryptedMessage(ctx, readCap, nil, nextIndexBytes, &replyIndex, envDesc, ciphertext, envHash, epoch)
		if err != nil {
			return fmt.Errorf("failed to read message %d: %w", i, err)
		}

		// Write plaintext to stdout
		_, err = os.Stdout.Write(plaintext)
		if err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}

		// Advance to next index using local BACAP computation (no RPC needed)
		currentIndex, err = currentIndex.NextIndex()
		if err != nil {
			return fmt.Errorf("failed to compute next index: %w", err)
		}
	}

	fmt.Fprintln(os.Stderr, "Done")
	return nil
}
