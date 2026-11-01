// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package voucher_router is the contact voucher protocol between clients,
// services and the voucher router, and the router itself: a mixnet service
// that relays sealed vouchers from clients to pigeonhole services. It cannot open what it
// relays. A service opens a link with the router by registering, which runs
// the contact voucher handshake with the router as inductor; afterwards the
// router writes each sealed voucher addressed to the service to its end of
// the link. A link is a lease: the service renews it before it expires, or
// unregisters, and the router forgets a link whose lease has passed.
package voucher_router

import (
	"context"
	"errors"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

const (
	// DedupTTL is how long a routed ciphertext is remembered, so a
	// retransmission is acknowledged without being forwarded again.
	DedupTTL = 5 * time.Minute

	// linkQueueSize bounds the vouchers waiting to be written to one link.
	linkQueueSize = 64

	// displayName is the name the router gives itself in a WhoReply.
	displayName = "voucher router"

	// DefaultMaxInductions is the default bound on registrations being
	// inducted at once.
	DefaultMaxInductions = 64

	// DefaultInductTimeout is the default time a registration has to
	// complete its induction.
	DefaultInductTimeout = 10 * time.Minute

	// DefaultMaxRetained is the default bound on the vouchers one link
	// keeps rewritten.
	DefaultMaxRetained = 4096

	// MaxLinkTTL is the longest lease a router grants a link: a service
	// renews within it or loses the link.
	MaxLinkTTL = 7 * 24 * time.Hour

	// DefaultMaxLinks is the default bound on the links a router holds.
	DefaultMaxLinks = 4096

	// sweepInterval is how often expired links and leases are forgotten.
	sweepInterval = time.Hour
)

var linksBucket = []byte("links")

// Config configures a Router.
type Config struct {
	// Key is the router's NIKE keypair, published in the PKI.
	Key *common.PluginKey
	// DBPath is the file holding the router's links.
	DBPath string
	// PollInterval is how often a pending read is retried.
	PollInterval time.Duration
	// Retention is how long a forwarded voucher is kept rewritten.
	Retention time.Duration
	// MaxInductions bounds the registrations being inducted at once; a
	// registration beyond it is refused with StatusBusy. Zero or less
	// selects DefaultMaxInductions.
	MaxInductions int
	// InductTimeout is how long a registration has to complete its
	// induction before the router abandons it. Zero or less selects
	// DefaultInductTimeout.
	InductTimeout time.Duration
	// MaxRetained bounds the vouchers one link keeps rewritten; routes to
	// a link holding that many are refused with StatusBusy until they
	// pass retention. Zero or less selects DefaultMaxRetained.
	MaxRetained int
	// MaxLinks bounds the links held and being inducted; a registration of
	// a new service beyond it is refused with StatusBusy. Zero or less
	// selects DefaultMaxLinks.
	MaxLinks int
	Log      *logging.Logger
}

type link struct {
	id    common.ServiceID
	conn  *Conn
	queue chan []byte
	stop  context.CancelFunc
	// done is closed when the link's writer has stopped.
	done chan struct{}
}

// lease is what the router remembers of a service's requests: the Seq of
// the last one applied, when its link expires (zero once unregistered),
// and when the record itself may be forgotten.
type lease struct {
	Seq, Expiry, Keep uint64
}

// linkRecord is a lease and its link's connection, if the link is open, as
// stored in the database.
type linkRecord struct {
	lease
	Conn *ConnState `cbor:",omitempty"`
}

// Router routes sealed vouchers to services.
type Router struct {
	cfg Config
	ph  common.Pigeonhole
	db  *bolt.DB
	log *logging.Logger
	now func() time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	links  map[common.ServiceID]*link
	leases map[common.ServiceID]lease
	// registering holds the vouchers being inducted, and registered the
	// vouchers inducted within DedupTTL, so a retransmitted registration
	// is acknowledged without being inducted again.
	registering map[[32]byte]bool
	registered  map[[32]byte]time.Time
	// pending queues vouchers for services whose link is still being
	// inducted: a service learns its link is open before the router has
	// finished inducting, and may advertise and be routed to at once.
	pending map[common.ServiceID]chan []byte
	routed  map[[32]byte]time.Time
}

// New opens the router's database and resumes its links.
func New(cfg Config, ph common.Pigeonhole) (*Router, error) {
	if cfg.Key == nil || cfg.Log == nil {
		return nil, errors.New("router: Key and Log are required")
	}
	db, err := bolt.Open(cfg.DBPath, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	if cfg.MaxInductions <= 0 {
		cfg.MaxInductions = DefaultMaxInductions
	}
	if cfg.InductTimeout <= 0 {
		cfg.InductTimeout = DefaultInductTimeout
	}
	if cfg.MaxRetained <= 0 {
		cfg.MaxRetained = DefaultMaxRetained
	}
	if cfg.MaxLinks <= 0 {
		cfg.MaxLinks = DefaultMaxLinks
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Router{
		cfg:         cfg,
		ph:          ph,
		db:          db,
		log:         cfg.Log,
		now:         time.Now,
		ctx:         ctx,
		cancel:      cancel,
		links:       make(map[common.ServiceID]*link),
		leases:      make(map[common.ServiceID]lease),
		registering: make(map[[32]byte]bool),
		registered:  make(map[[32]byte]time.Time),
		pending:     make(map[common.ServiceID]chan []byte),
		routed:      make(map[[32]byte]time.Time),
	}
	if err := r.load(); err != nil {
		db.Close()
		cancel()
		return nil, err
	}
	r.sweep()
	r.wg.Add(1)
	go r.sweeper()
	return r, nil
}

// Close stops the router's link writers and closes its database.
func (r *Router) Close() error {
	r.cancel()
	r.wg.Wait()
	return r.db.Close()
}

func (r *Router) load() error {
	type restored struct {
		id   common.ServiceID
		conn *Conn
		seq  uint64
	}
	var links []restored
	err := r.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(linksBucket)
		if err != nil {
			return err
		}
		return b.ForEach(func(k, v []byte) error {
			var rec linkRecord
			if err := common.Unmarshal(v, &rec); err != nil {
				return err
			}
			id := common.ServiceID(k)
			r.leases[id] = rec.lease
			if rec.Conn == nil {
				return nil
			}
			conn, err := RestoreConn(r.ph, rec.Conn, r.cfg.PollInterval)
			if err != nil {
				return err
			}
			links = append(links, restored{id, conn, rec.Seq})
			return nil
		})
	})
	if err != nil {
		return err
	}
	// Outside the transaction: starting a link saves it.
	for _, l := range links {
		r.startLink(l.id, l.conn, nil, l.seq)
	}
	return nil
}

// save stores the link's lease and connection. The caller must not hold
// r.mu.
func (r *Router) save(id common.ServiceID, conn *Conn) error {
	st, err := conn.State()
	if err != nil {
		return err
	}
	r.mu.Lock()
	rec := linkRecord{lease: r.leases[id], Conn: st}
	r.mu.Unlock()
	return r.put(id, &rec)
}

func (r *Router) put(id common.ServiceID, rec *linkRecord) error {
	blob, err := common.Marshal(rec)
	if err != nil {
		return err
	}
	return r.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(linksBucket).Put(id[:], blob)
	})
}

// startLink installs a link, replacing any older link to the same service,
// unless a later request (by seq) has closed or replaced it meanwhile. A
// non-nil queue holds vouchers routed while the link was being inducted.
// Vouchers still queued for the older link move to the new one. The caller
// must not hold r.mu.
func (r *Router) startLink(id common.ServiceID, conn *Conn, queue chan []byte, seq uint64) {
	if queue == nil {
		queue = make(chan []byte, linkQueueSize)
	}
	ctx, stop := context.WithCancel(r.ctx)
	l := &link{id: id, conn: conn, queue: queue, stop: stop, done: make(chan struct{})}
	r.mu.Lock()
	if r.pending[id] == queue {
		delete(r.pending, id)
	}
	if r.leases[id].Seq != seq {
		r.mu.Unlock()
		stop()
		return
	}
	old := r.links[id]
	r.links[id] = l
	r.mu.Unlock()
	r.wg.Add(1)
	go r.writeLink(ctx, l)
	if err := r.save(id, conn); err != nil {
		r.log.Errorf("saving link: %v", err)
	}
	if old != nil {
		old.stop()
		<-old.done
		// The old writer may have saved its link last.
		if err := r.save(id, conn); err != nil {
			r.log.Errorf("saving link: %v", err)
		}
		r.requeue(old.queue, l.queue)
	}
}

// requeue moves the vouchers waiting in from to to, dropping any that do
// not fit.
func (r *Router) requeue(from, to chan []byte) {
	for {
		select {
		case c := <-from:
			select {
			case to <- c:
			default:
				r.log.Warningf("dropping a voucher: link queue full")
			}
		default:
			return
		}
	}
}

// writeLink writes the vouchers routed to one service, in order, and keeps
// them rewritten until they pass retention.
func (r *Router) writeLink(ctx context.Context, l *link) {
	defer r.wg.Done()
	defer close(l.done)
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
			msg, err := common.Marshal(&LinkMessage{Forward: ciphertext})
			if err != nil {
				r.log.Errorf("encoding link message: %v", err)
				continue
			}
			if err := l.conn.Send(ctx, msg); err != nil {
				if ctx.Err() != nil {
					// Stopped: hand it to whoever takes over the queue.
					select {
					case l.queue <- ciphertext:
					default:
					}
					return
				}
				r.log.Errorf("writing link: %v", err)
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

func (r *Router) sweeper() {
	defer r.wg.Done()
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
			r.sweep()
		}
	}
}

// sweep closes the links whose lease has expired and forgets the leases
// that may be forgotten.
func (r *Router) sweep() {
	now := uint64(r.now().Unix())
	var expired []*link
	var forget []common.ServiceID
	r.mu.Lock()
	for id, le := range r.leases {
		if l := r.links[id]; l != nil && le.Expiry <= now {
			delete(r.links, id)
			expired = append(expired, l)
			le.Expiry = 0
			r.leases[id] = le
		}
		if r.links[id] == nil && le.Keep <= now {
			delete(r.leases, id)
			forget = append(forget, id)
		}
	}
	r.mu.Unlock()
	for _, l := range expired {
		l.stop()
		<-l.done
		r.mu.Lock()
		le, kept := r.leases[l.id]
		r.mu.Unlock()
		if kept {
			if err := r.put(l.id, &linkRecord{lease: le}); err != nil {
				r.log.Errorf("saving lease: %v", err)
			}
		}
		r.log.Noticef("link with service %x expired", l.id[:8])
	}
	if len(forget) > 0 {
		err := r.db.Update(func(tx *bolt.Tx) error {
			for _, id := range forget {
				if err := tx.Bucket(linksBucket).Delete(id[:]); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			r.log.Errorf("forgetting leases: %v", err)
		}
	}
}

// Handle serves one request and returns the encoded reply. It returns at
// once: registrations and forwarding complete in the background.
func (r *Router) Handle(payload []byte) []byte {
	b, err := common.Marshal(r.handle(payload))
	if err != nil {
		r.log.Errorf("encoding reply: %v", err)
		return nil
	}
	return b
}

func (r *Router) handle(payload []byte) *RouterReply {
	var req RouterRequest
	if err := common.Unmarshal(payload, &req); err != nil {
		return &RouterReply{Status: common.StatusInvalidRequest}
	}
	set := 0
	for _, p := range []bool{req.Route != nil, req.Register != nil, req.Renew != nil, req.Unregister != nil} {
		if p {
			set++
		}
	}
	if set != 1 {
		return &RouterReply{Status: common.StatusInvalidRequest}
	}
	switch {
	case req.Route != nil:
		return &RouterReply{Status: r.route(req.Route)}
	case req.Register != nil:
		return r.register(req.Register)
	case req.Renew != nil:
		return r.renew(req.Renew)
	default:
		return &RouterReply{Status: r.unregister(req.Unregister)}
	}
}

func (r *Router) route(req *RouteRequest) uint8 {
	if len(req.Ciphertext) == 0 {
		return common.StatusInvalidRequest
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
	// A registration being inducted replaces the link the service has, if
	// any: a service registers again when it has lost that link.
	var queue chan []byte
	if q, ok := r.pending[req.ServiceID]; ok {
		queue = q
	} else if l, ok := r.links[req.ServiceID]; ok && r.leases[req.ServiceID].Expiry > uint64(r.now().Unix()) {
		if l.conn.Retained()+len(l.queue) >= r.cfg.MaxRetained {
			return common.StatusBusy
		}
		queue = l.queue
	} else {
		return common.StatusUnknownService
	}
	if _, seen := r.routed[key]; seen {
		return common.StatusOK
	}
	select {
	case queue <- req.Ciphertext:
		r.routed[key] = now
		return common.StatusOK
	default:
		return common.StatusBusy
	}
}

func (r *Router) register(req *RegisterRequest) *RouterReply {
	if err := VerifyRegister(r.cfg.Key, req); err != nil {
		return &RouterReply{Status: common.StatusBadMAC}
	}
	keep, ok := common.CheckLease(r.now(), req.Expiry, MaxLinkTTL)
	if len(req.Voucher) != 32 || !ok {
		return &RouterReply{Status: common.StatusInvalidRequest}
	}
	key := hash.Sum256(req.Voucher)
	now := time.Now()
	id := common.IDFromPublicKey(req.PublicKey)
	r.mu.Lock()
	for k, at := range r.registered {
		if now.Sub(at) > DedupTTL {
			delete(r.registered, k)
		}
	}
	if _, done := r.registered[key]; done || r.registering[key] {
		expiry := r.leases[id].Expiry
		r.mu.Unlock()
		return &RouterReply{Status: common.StatusOK, Expiry: expiry}
	}
	cur := r.leases[id]
	if req.Seq <= cur.Seq {
		r.mu.Unlock()
		return &RouterReply{Status: common.StatusStale}
	}
	if len(r.registering) >= r.cfg.MaxInductions {
		r.mu.Unlock()
		return &RouterReply{Status: common.StatusBusy}
	}
	queue, inducting := r.pending[id]
	if _, linked := r.links[id]; !linked && !inducting && len(r.links)+len(r.pending) >= r.cfg.MaxLinks {
		r.mu.Unlock()
		return &RouterReply{Status: common.StatusBusy}
	}
	r.registering[key] = true
	r.leases[id] = lease{Seq: req.Seq, Expiry: req.Expiry, Keep: max(cur.Keep, keep)}
	if !inducting {
		queue = make(chan []byte, linkQueueSize)
		r.pending[id] = queue
	}
	r.mu.Unlock()

	voucher := append([]byte(nil), req.Voucher...)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ctx, cancel := context.WithTimeout(r.ctx, r.cfg.InductTimeout)
		defer cancel()
		conn, err := Induct(ctx, r.ph, voucher, displayName, r.cfg.PollInterval)
		if err != nil {
			if r.ctx.Err() == nil {
				r.log.Errorf("inducting a service: %v", err)
			}
			r.mu.Lock()
			delete(r.registering, key)
			if r.pending[id] == queue {
				delete(r.pending, id)
			}
			old := r.links[id]
			r.mu.Unlock()
			if old != nil {
				r.requeue(queue, old.queue)
			}
			return
		}
		r.startLink(id, conn, queue, req.Seq)
		r.mu.Lock()
		delete(r.registering, key)
		r.registered[key] = time.Now()
		r.mu.Unlock()
		r.log.Noticef("opened a link with service %x", id[:8])
	}()
	return &RouterReply{Status: common.StatusOK, Expiry: req.Expiry}
}

func (r *Router) renew(req *RenewRequest) *RouterReply {
	if err := VerifyRenew(r.cfg.Key, req); err != nil {
		return &RouterReply{Status: common.StatusBadMAC}
	}
	keep, ok := common.CheckLease(r.now(), req.Expiry, MaxLinkTTL)
	if !ok {
		return &RouterReply{Status: common.StatusInvalidRequest}
	}
	id := common.IDFromPublicKey(req.PublicKey)
	r.mu.Lock()
	cur := r.leases[id]
	switch {
	case req.Seq == cur.Seq && req.Expiry == cur.Expiry:
		// A retransmission of the request already applied.
	case req.Seq <= cur.Seq:
		r.mu.Unlock()
		return &RouterReply{Status: common.StatusStale}
	case r.links[id] == nil || cur.Expiry <= uint64(r.now().Unix()):
		r.mu.Unlock()
		return &RouterReply{Status: common.StatusUnknownService}
	default:
		r.leases[id] = lease{Seq: req.Seq, Expiry: req.Expiry, Keep: max(cur.Keep, keep)}
	}
	l := r.links[id]
	r.mu.Unlock()
	if l != nil {
		if err := r.save(id, l.conn); err != nil {
			r.log.Errorf("saving link: %v", err)
		}
	}
	return &RouterReply{Status: common.StatusOK, Expiry: req.Expiry}
}

func (r *Router) unregister(req *UnregisterRequest) uint8 {
	if err := VerifyUnregister(r.cfg.Key, req); err != nil {
		return common.StatusBadMAC
	}
	id := common.IDFromPublicKey(req.PublicKey)
	r.mu.Lock()
	cur, known := r.leases[id]
	l := r.links[id]
	switch {
	case !known:
		r.mu.Unlock()
		return common.StatusUnknownService
	case req.Seq == cur.Seq && l == nil && cur.Expiry == 0:
		// A retransmission of the request already applied.
		r.mu.Unlock()
		return common.StatusOK
	case req.Seq <= cur.Seq:
		r.mu.Unlock()
		return common.StatusStale
	}
	delete(r.links, id)
	delete(r.pending, id)
	le := lease{Seq: req.Seq, Keep: cur.Keep}
	r.leases[id] = le
	r.mu.Unlock()
	if l != nil {
		l.stop()
		<-l.done
	}
	if err := r.put(id, &linkRecord{lease: le}); err != nil {
		r.log.Errorf("saving lease: %v", err)
	}
	r.log.Noticef("service %x unregistered", id[:8])
	return common.StatusOK
}

// Linked reports whether the router holds a link with a service.
func (r *Router) Linked(id common.ServiceID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.links[id]
	return ok && r.leases[id].Expiry > uint64(r.now().Unix())
}
