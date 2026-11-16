// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// box is a debugging tool: it reads and writes single Pigeonhole boxes
// through a running kpclientd, with capabilities given as hex on the command
// line, the way pigeonhole-rns does on the Reticulum side of a bridge.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/thin"
)

var (
	configFile string
	logLevel   string
	timeout    time.Duration
	index      uint64
	writeCap   string
	readCap    string
)

func main() {
	root := &cobra.Command{
		Use:   "box",
		Short: "Read and write single Pigeonhole boxes through kpclientd (a debugging tool)",
		Long: `box reads and writes one Pigeonhole box at a time through a running
kpclientd. Capabilities are hex, as printed by new-cap and by the
pigeonhole-rns tool, so a box written on one side of a Reticulum bridge can
be read on the other. The index counts boxes from the capability's first.`,
		SilenceUsage: true,
	}
	root.PersistentFlags().StringVarP(&configFile, "config", "f", "/etc/katzenpost/thinclient.toml", "thin client config file")
	root.PersistentFlags().StringVarP(&logLevel, "log_level", "l", "ERROR", "thin client log level")
	root.PersistentFlags().DurationVar(&timeout, "timeout", 10*time.Minute, "how long to keep retrying through the mixnet")

	newCap := &cobra.Command{
		Use:   "new-cap",
		Short: "Print a fresh write capability and its read capability",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return runNewCap() },
	}

	write := &cobra.Command{
		Use:   "write <text>",
		Short: "Write text into the box at --index of a write capability's stream",
		Args:  cobra.ExactArgs(1),
		RunE:  func(_ *cobra.Command, args []string) error { return runWrite(args[0]) },
	}
	write.Flags().StringVar(&writeCap, "writecap", "", "hex write capability")
	write.Flags().Uint64Var(&index, "index", 0, "box index counted from the capability's first")
	_ = write.MarkFlagRequired("writecap")

	read := &cobra.Command{
		Use:   "read",
		Short: "Read the box at --index of a read capability's stream and print its text",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return runRead() },
	}
	read.Flags().StringVar(&readCap, "readcap", "", "hex read capability")
	read.Flags().Uint64Var(&index, "index", 0, "box index counted from the capability's first")
	_ = read.MarkFlagRequired("readcap")

	root.AddCommand(newCap, write, read)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runNewCap() error {
	w, err := bacap.NewWriteCap(rand.Reader)
	if err != nil {
		return err
	}
	wb, err := w.MarshalBinary()
	if err != nil {
		return err
	}
	rb, err := w.ReadCap().MarshalBinary()
	if err != nil {
		return err
	}
	fmt.Printf("writecap %s\nreadcap  %s\n", hex.EncodeToString(wb), hex.EncodeToString(rb))
	return nil
}

func runWrite(text string) error {
	raw, err := hex.DecodeString(strings.TrimSpace(writeCap))
	if err != nil {
		return fmt.Errorf("writecap: %w", err)
	}
	w, err := bacap.NewWriteCapFromBytes(raw)
	if err != nil {
		return fmt.Errorf("writecap: %w", err)
	}
	pos := w.Start()
	if index > 0 {
		if pos, err = pos.AdvanceTo(pos.Index().Idx64 + index); err != nil {
			return err
		}
	}
	return withClient(func(ctx context.Context, c *thin.ThinClient) error {
		idx := pos.Index()
		ciphertext, envDesc, envHash, _, err := c.EncryptWrite([]byte(text), w, idx)
		if err != nil {
			return err
		}
		idxBytes, err := idx.MarshalBinary()
		if err != nil {
			return err
		}
		replyIndex := uint8(0)
		if _, err := c.StartResendingEncryptedMessageWithContext(ctx, nil, w, idxBytes, &replyIndex, envDesc, ciphertext, envHash); err != nil {
			return err
		}
		boxID, err := pos.BoxID(constants.PIGEONHOLE_CTX)
		if err != nil {
			return err
		}
		fmt.Printf("%s written\n", hex.EncodeToString(boxID.Bytes()))
		return nil
	})
}

func runRead() error {
	raw, err := hex.DecodeString(strings.TrimSpace(readCap))
	if err != nil {
		return fmt.Errorf("readcap: %w", err)
	}
	r := bacap.NewEmptyReadCap()
	if err := r.UnmarshalBinary(raw); err != nil {
		return fmt.Errorf("readcap: %w", err)
	}
	pos := r.Start()
	if index > 0 {
		if pos, err = pos.AdvanceTo(pos.Index().Idx64 + index); err != nil {
			return err
		}
	}
	return withClient(func(ctx context.Context, c *thin.ThinClient) error {
		idx := pos.Index()
		ciphertext, envDesc, envHash, _, err := c.EncryptRead(r, idx)
		if err != nil {
			return err
		}
		idxBytes, err := idx.MarshalBinary()
		if err != nil {
			return err
		}
		res, err := c.StartResendingEncryptedMessageWithContext(ctx, r, nil, idxBytes, nil, envDesc, ciphertext, envHash)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", res.Plaintext)
		return nil
	})
}

func withClient(fn func(context.Context, *thin.ThinClient) error) error {
	cfg, err := thin.LoadFile(configFile)
	if err != nil {
		return err
	}
	c := thin.NewThinClient(cfg, &config.Logging{Level: logLevel})
	if err := c.Dial(); err != nil {
		return fmt.Errorf("kpclientd: %w", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return fn(ctx, c)
}
