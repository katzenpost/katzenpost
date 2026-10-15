// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/common"
)

const headerTimeout = 5 * time.Minute

type options struct {
	configFile string
	logFile    string
	logLevel   string
	window     int
}

type boxes struct {
	c     *thin.ThinClient
	first *bacap.MessageBoxIndex
}

func (s boxes) index(k uint64) (*bacap.MessageBoxIndex, error) {
	return s.first.AdvanceIndexTo(s.first.Idx64 + k)
}

func (s boxes) write(writeCap *bacap.WriteCap, k uint64, b []byte) error {
	idx, err := s.index(k)
	if err != nil {
		return err
	}
	ct, desc, hash, _, err := s.c.EncryptWrite(b, writeCap, idx)
	if err != nil {
		return err
	}
	reply := uint8(0)
	_, err = s.c.StartResendingEncryptedMessage(nil, writeCap, nil, &reply, desc, ct, hash)
	return err
}

func (s boxes) read(ctx context.Context, readCap *bacap.ReadCap, k uint64, retry bool) ([]byte, error) {
	idx, err := s.index(k)
	if err != nil {
		return nil, err
	}
	ct, desc, hash, _, err := s.c.EncryptRead(readCap, idx)
	if err != nil {
		return nil, err
	}
	idxBytes, err := idx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	reply := uint8(0)
	var r *thin.StartResendingResult
	if retry {
		r, err = s.c.StartResendingEncryptedMessageWithContext(ctx, readCap, nil, idxBytes, &reply, desc, ct, hash)
	} else {
		r, err = s.c.StartResendingEncryptedMessageNoRetry(readCap, nil, idxBytes, &reply, desc, ct, hash)
	}
	if ctx.Err() != nil {
		s.c.CancelResendingEncryptedMessage(hash)
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return r.Plaintext, nil
}

func dial(o *options) (*thin.ThinClient, error) {
	cfg, err := thin.LoadFile(o.configFile)
	if err != nil {
		return nil, err
	}
	c := thin.NewThinClient(cfg, &config.Logging{Disable: o.logFile == "", File: o.logFile, Level: o.logLevel})
	if err := c.Dial(); err != nil {
		return nil, err
	}
	return c, nil
}

func createReadCapFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func runSend(ctx context.Context, o *options, in io.Reader, status io.Writer, readCapFile string) error {
	readCapOut := status
	if readCapFile != "" {
		f, err := createReadCapFile(readCapFile)
		if err != nil {
			return err
		}
		defer f.Close()
		readCapOut = f
	}
	c, err := dial(o)
	if err != nil {
		return err
	}
	defer c.Close()
	seed := make([]byte, 32)
	if _, err := rand.Reader.Read(seed); err != nil {
		return err
	}
	writeCap, readCap, first, err := c.NewKeypair(seed)
	if err != nil {
		return err
	}
	rc, err := readCap.MarshalBinary()
	if err != nil {
		return err
	}
	s := boxes{c: c, first: first}
	geo := c.GetPigeonholeGeometry()
	published := func() {
		if _, err := fmt.Fprintln(readCapOut, hex.EncodeToString(rc)); err != nil {
			fmt.Fprintf(status, "kp-fa: %v\n", err)
		}
	}
	write := func(k uint64, b []byte) error { return s.write(writeCap, k, b) }
	err = send(stoppable(ctx, in), geo.MaxPlaintextPayloadLength, o.window, write, published)
	if ctx.Err() != nil && errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil
	}
	if err == nil {
		fmt.Fprintln(status, "kp-fa: end of broadcast sent, off the air")
	}
	return err
}

func runListen(ctx context.Context, o *options, readCapHex string, fromStart bool, back uint64, stall time.Duration, out, status io.Writer) error {
	raw, err := hex.DecodeString(strings.TrimSpace(readCapHex))
	if err != nil {
		return err
	}
	readCap, err := bacap.ReadCapFromBytes(raw)
	if err != nil {
		return err
	}
	c, err := dial(o)
	if err != nil {
		return err
	}
	defer c.Close()
	s := boxes{c: c, first: readCap.GetMessageBoxIndex()}
	hctx, cancel := context.WithTimeout(ctx, headerTimeout)
	hb, err := s.read(hctx, readCap, 0, true)
	cancel()
	if err != nil {
		return fmt.Errorf("kp-fa: stream header unreadable (not started or expired): %w", err)
	}
	h, err := unmarshalFrame(hb)
	if err != nil {
		return err
	}
	codec, init, err := parseHeaderBody(h.body)
	if err != nil {
		return err
	}
	if h.kind != kindHeader || codec != codecOpus {
		return fmt.Errorf("kp-fa: not a %s stream header", codecOpus)
	}
	var frontier uint64
	seen := map[uint64][]byte{}
	if !fromStart {
		frontier, err = findFrontier(func(k uint64) (bool, error) {
			b, err := s.read(ctx, readCap, k, false)
			if errors.Is(err, thin.ErrBoxIDNotFound) {
				return false, nil
			}
			seen[k] = b
			return err == nil, err
		})
		if err != nil {
			return err
		}
	}
	last, err := unmarshalFrame(seen[frontier])
	ended := err == nil && last.kind == kindEnd
	start := startBox(frontier, back, fromStart, ended)
	fmt.Fprintf(status, "kp-fa: frontier %d, ended %v, starting at box %d\n", frontier, ended, start)
	rctx, stop := context.WithCancel(ctx)
	defer stop()
	next := ordered(rctx, o.window, start, stall, func(ctx context.Context, k uint64) ([]byte, error) {
		return s.read(ctx, readCap, k, true)
	})
	if err := play(out, init, next); err != nil {
		return err
	}
	fmt.Fprintln(status, "kp-fa: broadcast ended, signing off")
	return nil
}

func newRootCommand(ctx context.Context) *cobra.Command {
	o := &options{}
	root := &cobra.Command{
		Use:   "kp-fa",
		Short: "katzenpost finite audio: pirate radio over pigeonhole",
		Example: `  kp-fa -c thinclient.toml broadcast < show.opus
  ffmpeg -f pulse -i default -c:a libopus -b:a 6k -ac 1 -f ogg - | kp-fa -c thinclient.toml on-air
  kp-fa -c thinclient.toml tune-in <readcap> | mpv -`,
		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			if o.window < 1 {
				return fmt.Errorf("kp-fa: --window %d, want at least 1", o.window)
			}
			return nil
		},
	}
	root.PersistentFlags().StringVarP(&o.configFile, "config", "c", "", "thin client configuration file")
	root.PersistentFlags().StringVar(&o.logFile, "log-file", "", "thin client log file; logging is off when empty")
	root.PersistentFlags().StringVar(&o.logLevel, "log-level", "INFO", "logging level")
	root.PersistentFlags().IntVar(&o.window, "window", 4, "boxes in flight")
	root.MarkPersistentFlagRequired("config")

	var readCapFile string
	sendCmd := &cobra.Command{
		Use:     "send",
		Aliases: []string{"broadcast", "on-air"},
		Short:   "Go on the air: broadcast Ogg/Opus from stdin, print the read capability",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSend(ctx, o, cmd.InOrStdin(), cmd.ErrOrStderr(), readCapFile)
		},
	}
	sendCmd.Flags().StringVar(&readCapFile, "readcap-file", "", "write the read capability to this new file instead of stderr")

	var fromStart bool
	var back uint64
	var stall time.Duration
	listenCmd := &cobra.Command{
		Use:     "listen <readcap>",
		Aliases: []string{"tune-in"},
		Short:   "Tune in to a broadcast: audio to stdout until it signs off",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if stall <= 0 {
				return fmt.Errorf("kp-fa: --stall-timeout %s, want more than zero", stall)
			}
			return runListen(ctx, o, args[0], fromStart, back, stall, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	listenCmd.Flags().BoolVar(&fromStart, "from-start", false, "play from the first box")
	listenCmd.Flags().Uint64Var(&back, "back", 0, "start this many boxes behind the newest")
	listenCmd.Flags().DurationVar(&stall, "stall-timeout", 5*time.Minute, "give up when no new audio arrives for this long")
	listenCmd.MarkFlagsMutuallyExclusive("from-start", "back")

	root.AddCommand(sendCmd, listenCmd)
	return root
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	context.AfterFunc(ctx, stop)
	common.ExecuteWithFang(newRootCommand(ctx))
}
