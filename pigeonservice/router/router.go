// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package router is the voucher router: a mixnet service that relays sealed
// vouchers from clients to pigeonhole services. It cannot open what it
// relays. A service opens a link with the router by registering, which runs
// the contact voucher handshake with the router as inductor; afterwards the
// router writes each sealed voucher addressed to the service to its end of
// the link.
package router

import (
	"context"
	"errors"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"

	ps "github.com/katzenpost/katzenpost/pigeonservice"
)

const (
	// DedupTTL is how long a routed ciphertext is remembered, so a
	// retransmission is acknowledged without being forwarded again.
	DedupTTL = 5 * time.Minute

	// linkQueueSize bounds the vouchers waiting to be written to one link.
	linkQueueSize = 64

	// displayName is the name the router gives itself in a WhoReply.
	displayName = "voucher router"
)

var linksBucket = []byte("links")

// Config configures a Router.
type Config struct {
	// Key is the router's NIKE keypair, published in the PKI.
	Key *ps.PluginKey
	// DBPath is the file holding the router's links.
	DBPath string
	// PollInterval is how often a pending read is retried.
	PollInterval time.Duration
	// Retention is how long a forwarded voucher is kept rewritten.
	Retention time.Duration
	Log       *logging.Logger
}

type link struct {
	id    ps.ServiceID
	conn  *ps.Conn
	queue chan []byte
	stop  context.CancelFunc
}

// Router routes sealed vouchers to services.
type Router struct {
	cfg Config
	ph  ps.Pigeonhole
	db  *bolt.DB
	log *logging.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu          sync.Mutex
	links       map[ps.ServiceID]*link
	registering map[[32]byte]bool
	routed      map[[32]byte]time.Time
}

// New opens the router's database and resumes its links.
func New(cfg Config, ph ps.Pigeonhole) (*Router, error) {
	if cfg.Key == nil || cfg.Log == nil {
		return nil, errors.New("router: Key and Log are required")
	}
	db, err := bolt.Open(cfg.DBPath, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Router{
		cfg:         cfg,
		ph:          ph,
		db:          db,
		log:         cfg.Log,
		ctx:         ctx,
		cancel:      cancel,
		links:       make(map[ps.ServiceID]*link),
		registering: make(map[[32]byte]bool),
		routed:      make(map[[32]byte]time.Time),
	}
	if err := r.load(); err != nil {
		db.Close()
		cancel()
		return nil, err
	}
	return r, nil
}

// Close stops the router's link writers and closes its database.
func (r *Router) Close() error {
	r.cancel()
	r.wg.Wait()
	return r.db.Close()
}

func (r *Router) load() error {
	return r.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(linksBucket)
		if err != nil {
			return err
		}
		return b.ForEach(func(k, v []byte) error {
			var st ps.ConnState
			if err := ps.Unmarshal(v, &st); err != nil {
				return err
			}
			conn, err := ps.RestoreConn(r.ph, &st, r.cfg.PollInterval)
			if err != nil {
				return err
			}
			r.startLink(ps.ServiceID(k), conn)
			return nil
		})
	})
}

func (r *Router) save(id ps.ServiceID, conn *ps.Conn) error {
	st, err := conn.State()
	if err != nil {
		return err
	}
	blob, err := ps.Marshal(st)
	if err != nil {
		return err
	}
	return r.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(linksBucket).Put(id[:], blob)
	})
}

// startLink installs a link, replacing any older link to the same service.
// The caller must not hold r.mu.
func (r *Router) startLink(id ps.ServiceID, conn *ps.Conn) {
	ctx, stop := context.WithCancel(r.ctx)
	l := &link{id: id, conn: conn, queue: make(chan []byte, linkQueueSize), stop: stop}
	r.mu.Lock()
	if old, ok := r.links[id]; ok {
		old.stop()
	}
	r.links[id] = l
	r.mu.Unlock()
	r.wg.Add(1)
	go r.writeLink(ctx, l)
}

// writeLink writes the vouchers routed to one service, in order, and keeps
// them rewritten until they pass retention.
func (r *Router) writeLink(ctx context.Context, l *link) {
	defer r.wg.Done()
	refresh := time.NewTicker(refreshInterval(r.cfg.Retention))
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			if err := l.conn.Refresh(ctx, r.cfg.Retention); err != nil && ctx.Err() == nil {
				r.log.Warningf("refreshing link: %v", err)
			}
			if err := r.save(l.id, l.conn); err != nil {
				r.log.Errorf("saving link: %v", err)
			}
		case ciphertext := <-l.queue:
			msg, err := ps.Marshal(&ps.LinkMessage{Forward: ciphertext})
			if err != nil {
				r.log.Errorf("encoding link message: %v", err)
				continue
			}
			if err := l.conn.Send(ctx, msg); err != nil {
				if ctx.Err() == nil {
					r.log.Errorf("writing link: %v", err)
				}
				continue
			}
			if err := r.save(l.id, l.conn); err != nil {
				r.log.Errorf("saving link: %v", err)
			}
		}
	}
}

func refreshInterval(retention time.Duration) time.Duration {
	if retention <= 0 {
		return 24 * time.Hour
	}
	return max(retention/7, time.Minute)
}

// Handle serves one request and returns the encoded reply. It returns at
// once: registrations and forwarding complete in the background.
func (r *Router) Handle(payload []byte) []byte {
	reply := &ps.RouterReply{Status: r.handle(payload)}
	b, err := ps.Marshal(reply)
	if err != nil {
		r.log.Errorf("encoding reply: %v", err)
		return nil
	}
	return b
}

func (r *Router) handle(payload []byte) uint8 {
	var req ps.RouterRequest
	if err := ps.Unmarshal(payload, &req); err != nil {
		return ps.StatusInvalidRequest
	}
	switch {
	case req.Route != nil && req.Register == nil:
		return r.route(req.Route)
	case req.Register != nil && req.Route == nil:
		return r.register(req.Register)
	default:
		return ps.StatusInvalidRequest
	}
}

func (r *Router) route(req *ps.RouteRequest) uint8 {
	if len(req.Ciphertext) == 0 {
		return ps.StatusInvalidRequest
	}
	key := hash.Sum256(req.Ciphertext)
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	for k, at := range r.routed {
		if now.Sub(at) > DedupTTL {
			delete(r.routed, k)
		}
	}
	l, ok := r.links[req.ServiceID]
	if !ok {
		return ps.StatusUnknownService
	}
	if _, seen := r.routed[key]; seen {
		return ps.StatusOK
	}
	select {
	case l.queue <- req.Ciphertext:
		r.routed[key] = now
		return ps.StatusOK
	default:
		return ps.StatusBusy
	}
}

func (r *Router) register(req *ps.RegisterRequest) uint8 {
	if err := r.cfg.Key.VerifyRegister(req); err != nil {
		return ps.StatusBadMAC
	}
	if len(req.Voucher) != 32 {
		return ps.StatusInvalidRequest
	}
	key := hash.Sum256(req.Voucher)
	r.mu.Lock()
	if r.registering[key] {
		r.mu.Unlock()
		return ps.StatusOK
	}
	r.registering[key] = true
	r.mu.Unlock()

	id := ps.IDFromPublicKey(req.PublicKey)
	voucher := append([]byte(nil), req.Voucher...)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		conn, err := ps.Induct(r.ctx, r.ph, voucher, displayName, r.cfg.PollInterval)
		if err != nil {
			if r.ctx.Err() == nil {
				r.log.Errorf("inducting a service: %v", err)
			}
			r.mu.Lock()
			delete(r.registering, key)
			r.mu.Unlock()
			return
		}
		if err := r.save(id, conn); err != nil {
			r.log.Errorf("saving link: %v", err)
		}
		r.startLink(id, conn)
		r.log.Noticef("opened a link with service %x", id[:8])
	}()
	return ps.StatusOK
}

// Linked reports whether the router holds a link with a service.
func (r *Router) Linked(id ps.ServiceID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.links[id]
	return ok
}
