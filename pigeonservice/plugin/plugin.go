// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package plugin runs a pigeonservice mixnet service, the voucher router or
// the service directory, as a Katzenpost CBOR plugin. The service talks to
// Pigeonhole through a thin client connected to a kpclientd on the service
// node.
package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

// maxConcurrent bounds the requests served at once.
const maxConcurrent = 64

// Handler serves one request payload.
type Handler interface {
	Handle(payload []byte) []byte
}

// Config configures a plugin.
type Config struct {
	// Name names the plugin in logs and files.
	Name string
	// LogDir and LogLevel configure logging.
	LogDir   string
	LogLevel string
	// DataDir holds the plugin's key and database.
	DataDir string
	// ThinConfig is the thin client config for the kpclientd to use.
	ThinConfig string
	// Busy is the reply sent while the plugin is not ready.
	Busy []byte
	// Start builds the handler once the thin client is connected.
	Start func(ph ps.Pigeonhole, key *ps.PluginKey, log *logging.Logger) (Handler, func(), error)
}

type plugin struct {
	cfg    Config
	log    *logging.Logger
	key    *ps.PluginKey
	write  func(cborplugin.Command)
	sem    chan struct{}
	mu     sync.Mutex
	h      Handler
	closer func()
}

func (p *plugin) OnCommand(cmd cborplugin.Command) error {
	r, ok := cmd.(*cborplugin.Request)
	if !ok {
		return fmt.Errorf("%s: invalid command type %T", p.cfg.Name, cmd)
	}
	if r.IsParametersRequest {
		go p.write(cborplugin.NewParametersResponse(ps.PluginParams(p.key)))
		return nil
	}
	select {
	case p.sem <- struct{}{}:
	default:
		p.log.Warning("too many requests in flight, dropping one")
		return nil
	}
	go func() {
		defer func() { <-p.sem }()
		p.mu.Lock()
		h := p.h
		p.mu.Unlock()
		reply := p.cfg.Busy
		if h != nil {
			reply = h.Handle(r.Payload)
		}
		p.write(&cborplugin.Response{
			ID:        r.ID,
			SURB:      r.SURB,
			Payload:   reply,
			RequestAt: r.RequestAt,
			Delay:     r.Delay,
		})
	}()
	return nil
}

func (p *plugin) RegisterConsumer(s *cborplugin.Server) {
	p.write = s.Write
}

// connect dials the thin client, retrying until it succeeds, then starts
// the handler.
func (p *plugin) connect(ctx context.Context) {
	for {
		cfg, err := thin.LoadFile(p.cfg.ThinConfig)
		if err != nil {
			p.log.Errorf("loading thin client config: %v", err)
			return
		}
		c := thin.NewThinClient(cfg, &config.Logging{
			File:  filepath.Join(p.cfg.LogDir, fmt.Sprintf("%s.thin.%d.log", p.cfg.Name, os.Getpid())),
			Level: p.cfg.LogLevel,
		})
		if err = c.Dial(); err == nil {
			h, closer, err := p.cfg.Start(ps.NewThinPigeonhole(c), p.key, p.log)
			if err != nil {
				p.log.Errorf("starting: %v", err)
				c.Close()
				return
			}
			p.mu.Lock()
			p.h, p.closer = h, closer
			p.mu.Unlock()
			p.log.Notice("connected to kpclientd, serving requests")
			return
		}
		p.log.Warningf("dialing kpclientd: %v, retrying", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// Run runs the plugin until the server stops it.
func Run(cfg Config) {
	fail := func(err error) { cborplugin.FailStartup(cfg.Name, err) }
	for _, dir := range []string{cfg.LogDir, cfg.DataDir} {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			fail(fmt.Errorf("%q is not a directory", dir))
		}
	}
	logBackend, err := log.New(filepath.Join(cfg.LogDir, fmt.Sprintf("%s.%d.log", cfg.Name, os.Getpid())), cfg.LogLevel, false)
	if err != nil {
		fail(err)
	}
	pluginLog := logBackend.GetLogger(cfg.Name)

	pub, priv, err := ps.LoadOrGenerateKeypair(cfg.DataDir, cfg.Name, ps.DefaultNIKE)
	if err != nil {
		fail(err)
	}
	p := &plugin{
		cfg: cfg,
		log: pluginLog,
		key: &ps.PluginKey{Scheme: ps.DefaultNIKE, Public: pub, Private: priv},
		sem: make(chan struct{}, maxConcurrent),
	}

	tmpDir, err := os.MkdirTemp("", cfg.Name)
	if err != nil {
		fail(err)
	}
	socketFile, fromHost := cborplugin.HostSocketPath(filepath.Join(tmpDir, fmt.Sprintf("%d.%s.socket", os.Getpid(), cfg.Name)))
	server := cborplugin.NewServer(pluginLog, socketFile, new(cborplugin.RequestFactory), p)
	if !fromHost {
		fmt.Printf("%s\n", socketFile)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go p.connect(ctx)

	server.Accept()
	server.Wait()
	cancel()
	p.mu.Lock()
	if p.closer != nil {
		p.closer()
	}
	p.mu.Unlock()
	_ = os.Remove(socketFile)
}
