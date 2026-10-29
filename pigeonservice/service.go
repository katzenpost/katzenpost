// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
)

var (
	linksBucket    = []byte("links")
	sessionsBucket = []byte("sessions")
)

const (
	// voucherDedupTTL is how long an opened voucher is remembered, so one
	// forwarded twice is handled once.
	voucherDedupTTL = time.Hour
	// incomingQueueSize bounds the vouchers waiting to be accepted.
	incomingQueueSize = 256
	// DefaultRegisterTimeout is the default time a registration has to
	// complete, longer than the router's default induction deadline.
	DefaultRegisterTimeout = 15 * time.Minute
	// DefaultHandshakeTimeout is the default time a client's voucher has
	// to be inducted before Run gives up on it.
	DefaultHandshakeTimeout = 10 * time.Minute
)

// rescanInterval is how often the service looks for new routers.
var rescanInterval = 10 * time.Minute

// LoadServiceKey loads the service's keypair from dataDir, generating one
// on first use.
func LoadServiceKey(dataDir string) (*ServiceKey, error) {
	pub, priv, err := LoadOrGenerateKeypair(dataDir, "service", DefaultNIKE)
	if err != nil {
		return nil, err
	}
	return &ServiceKey{Scheme: DefaultNIKE, Public: pub, Private: priv}, nil
}

// Config configures a Service.
type Config struct {
	// Key is the service's keypair; see LoadServiceKey.
	Key *ServiceKey
	// DataDir holds the service's database.
	DataDir string
	// DisplayName is the name the service gives itself to clients.
	DisplayName string
	// Advertiser publishes the service's descriptor; nil to not advertise.
	Advertiser Advertiser
	// PollInterval is how often a pending read is retried.
	PollInterval time.Duration
	// MaxConcurrentSessions bounds the sessions Run serves at once.
	MaxConcurrentSessions int
	// Retention is how long a sent message is kept rewritten.
	Retention time.Duration
	// RegisterTimeout is how long a registration with a router has to
	// complete before it is abandoned and retried on the next rescan;
	// zero means DefaultRegisterTimeout.
	RegisterTimeout time.Duration
	// HandshakeTimeout is how long Run waits for a client's handshake;
	// zero means DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	Log              *logging.Logger
}

// Handler serves one session. The session ends when OnSession returns.
type Handler interface {
	OnSession(ctx context.Context, s *Session)
}

// HandlerFunc adapts a function to a Handler.
type HandlerFunc func(ctx context.Context, s *Session)

// OnSession calls f.
func (f HandlerFunc) OnSession(ctx context.Context, s *Session) { f(ctx, s) }

// Session is a service's connection with one client.
type Session struct {
	*Conn
	id      [16]byte
	service *Service
}

// Close ends the session and forgets it.
func (s *Session) Close() error {
	return s.service.dropSession(s)
}

// Incoming is a client's opened voucher: the capability for one new
// session. Handshake turns it into the session.
type Incoming struct {
	service  *Service
	voucher  []byte
	restored *Session
}

// Handshake runs the service's side of the contact voucher handshake and
// returns the new session.
func (in *Incoming) Handshake(ctx context.Context) (*Session, error) {
	if in.restored != nil {
		return in.restored, nil
	}
	s := in.service
	conn, err := Induct(ctx, s.ph, in.voucher, s.cfg.DisplayName, s.cfg.PollInterval)
	if err != nil {
		return nil, err
	}
	sess := &Session{Conn: conn, service: s}
	if _, err := rand.Read(sess.id[:]); err != nil {
		return nil, err
	}
	if err := s.addSession(sess); err != nil {
		return nil, err
	}
	return sess, nil
}

// Listener yields the vouchers clients send the service.
type Listener struct {
	incoming chan *Incoming
	done     <-chan struct{}
}

// ErrClosed reports that the service has stopped.
var ErrClosed = errors.New("pigeonservice: service closed")

// Accept returns the next client's voucher.
func (l *Listener) Accept(ctx context.Context) (*Incoming, error) {
	select {
	case in := <-l.incoming:
		return in, nil
	case <-l.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Service is a pigeonhole service: it holds links with voucher routers,
// advertises them, and accepts the clients who reach it through them.
type Service struct {
	cfg Config
	ph  Pigeonhole
	key *ServiceKey
	db  *bolt.DB
	log *logging.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	incoming chan *Incoming

	mu          sync.Mutex
	links       map[[32]byte]*linkState
	registering map[[32]byte]bool
	sessions    map[[16]byte]*Session
	vouchers    map[[32]byte]time.Time
	listening   bool
}

type linkState struct {
	node ServiceNode
	conn *Conn
}

type storedLink struct {
	NodeIDHash [32]byte
	Endpoint   []byte
	Conn       ConnState
}

// NewService opens a service's database and restores its links and
// sessions. Call Listen or Run to start it.
func NewService(cfg Config, ph Pigeonhole) (*Service, error) {
	if cfg.Key == nil || cfg.Log == nil {
		return nil, errors.New("pigeonservice: Key and Log are required")
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = "service"
	}
	if cfg.MaxConcurrentSessions <= 0 {
		cfg.MaxConcurrentSessions = 64
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 7 * 24 * time.Hour
	}
	if cfg.RegisterTimeout <= 0 {
		cfg.RegisterTimeout = DefaultRegisterTimeout
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	db, err := bolt.Open(filepath.Join(cfg.DataDir, "service.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{
		cfg:         cfg,
		ph:          ph,
		key:         cfg.Key,
		db:          db,
		log:         cfg.Log,
		ctx:         ctx,
		cancel:      cancel,
		incoming:    make(chan *Incoming, incomingQueueSize),
		links:       make(map[[32]byte]*linkState),
		registering: make(map[[32]byte]bool),
		sessions:    make(map[[16]byte]*Session),
		vouchers:    make(map[[32]byte]time.Time),
	}
	if err := s.restore(); err != nil {
		db.Close()
		cancel()
		return nil, err
	}
	return s, nil
}

// Close stops the service.
func (s *Service) Close() error {
	s.cancel()
	s.wg.Wait()
	return s.db.Close()
}

// ID returns the service's ServiceID.
func (s *Service) ID() ServiceID {
	return s.key.ID()
}

// Descriptor returns the service's current descriptor.
func (s *Service) Descriptor() *ServiceDescriptor {
	d := &ServiceDescriptor{NIKEScheme: s.key.Scheme.Name(), PublicKey: s.key.Public.Bytes()}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.links {
		d.Routers = append(d.Routers, RouterRef{NodeIDHash: l.node.NodeIDHash, Endpoint: string(l.node.Endpoint)})
	}
	sort.Slice(d.Routers, func(i, j int) bool {
		return bytes.Compare(d.Routers[i].NodeIDHash[:], d.Routers[j].NodeIDHash[:]) < 0
	})
	return d
}

func (s *Service) restore() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		links, err := tx.CreateBucketIfNotExists(linksBucket)
		if err != nil {
			return err
		}
		sessions, err := tx.CreateBucketIfNotExists(sessionsBucket)
		if err != nil {
			return err
		}
		if err := links.ForEach(func(_, v []byte) error {
			var sl storedLink
			if err := Unmarshal(v, &sl); err != nil {
				return err
			}
			conn, err := RestoreConn(s.ph, &sl.Conn, s.cfg.PollInterval)
			if err != nil {
				return err
			}
			s.links[sl.NodeIDHash] = &linkState{node: ServiceNode{NodeIDHash: sl.NodeIDHash, Endpoint: sl.Endpoint}, conn: conn}
			return nil
		}); err != nil {
			return err
		}
		return sessions.ForEach(func(k, v []byte) error {
			var st ConnState
			if err := Unmarshal(v, &st); err != nil {
				return err
			}
			conn, err := RestoreConn(s.ph, &st, s.cfg.PollInterval)
			if err != nil {
				return err
			}
			sess := &Session{Conn: conn, service: s}
			copy(sess.id[:], k)
			s.sessions[sess.id] = sess
			return nil
		})
	})
}

func (s *Service) put(bucket, key []byte, v any) {
	blob, err := Marshal(v)
	if err == nil {
		err = s.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(bucket).Put(key, blob)
		})
	}
	if err != nil {
		s.log.Errorf("saving state: %v", err)
	}
}

func (s *Service) saveLink(l *linkState) {
	st, err := l.conn.State()
	if err != nil {
		s.log.Errorf("saving a link: %v", err)
		return
	}
	s.put(linksBucket, l.node.NodeIDHash[:], &storedLink{NodeIDHash: l.node.NodeIDHash, Endpoint: l.node.Endpoint, Conn: *st})
}

func (s *Service) saveSession(sess *Session) {
	st, err := sess.State()
	if err != nil {
		s.log.Errorf("saving a session: %v", err)
		return
	}
	s.mu.Lock()
	_, live := s.sessions[sess.id]
	s.mu.Unlock()
	if live {
		s.put(sessionsBucket, sess.id[:], st)
	}
}

func (s *Service) addSession(sess *Session) error {
	s.mu.Lock()
	s.sessions[sess.id] = sess
	s.mu.Unlock()
	sess.OnChange(func(*Conn) { s.saveSession(sess) })
	s.saveSession(sess)
	return nil
}

func (s *Service) dropSession(sess *Session) error {
	s.mu.Lock()
	delete(s.sessions, sess.id)
	s.mu.Unlock()
	sess.OnChange(nil)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(sessionsBucket).Delete(sess.id[:])
	})
}

// Listen starts the service: it resumes its links, registers with every
// router in the PKI it has no link with, advertises itself, and returns
// the listener for its clients. Sessions restored from the database are
// the first things Accept returns.
func (s *Service) Listen(ctx context.Context) (*Listener, error) {
	s.mu.Lock()
	if s.listening {
		s.mu.Unlock()
		return nil, errors.New("pigeonservice: already listening")
	}
	s.listening = true
	links := make([]*linkState, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	restored := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		restored = append(restored, sess)
	}
	s.mu.Unlock()

	for _, sess := range restored {
		sess.OnChange(func(*Conn) { s.saveSession(sess) })
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for _, sess := range restored {
			select {
			case s.incoming <- &Incoming{service: s, restored: sess}:
			case <-s.ctx.Done():
				return
			}
		}
	}()
	for _, l := range links {
		s.startLink(l)
	}
	s.wg.Add(2)
	go s.registrar()
	go s.refresher()
	if len(links) > 0 {
		s.advertise()
	}
	return &Listener{incoming: s.incoming, done: s.ctx.Done()}, nil
}

// Run listens and serves each session with h in its own goroutine, at most
// MaxConcurrentSessions at once, until ctx ends.
func (s *Service) Run(ctx context.Context, h Handler) error {
	l, err := s.Listen(ctx)
	if err != nil {
		return err
	}
	sem := make(chan struct{}, s.cfg.MaxConcurrentSessions)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		in, err := l.Accept(ctx)
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			hctx, cancel := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
			sess, err := in.Handshake(hctx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					s.log.Warningf("handshake with a client: %v", err)
				}
				return
			}
			h.OnSession(ctx, sess)
			// Sessions interrupted by shutdown are kept for the next Listen.
			if ctx.Err() == nil {
				_ = sess.Close()
			}
		}()
	}
}

func (s *Service) startLink(l *linkState) {
	l.conn.OnChange(func(*Conn) { s.saveLink(l) })
	s.wg.Add(1)
	go s.readLink(l)
}

// readLink reads the vouchers one router forwards.
func (s *Service) readLink(l *linkState) {
	defer s.wg.Done()
	for {
		msg, err := l.conn.Recv(s.ctx)
		if err != nil {
			if s.ctx.Err() == nil {
				s.log.Errorf("reading a link: %v", err)
			}
			return
		}
		voucher, err := openForward(s.key, msg)
		if err != nil {
			s.log.Warningf("a router forwarded something that does not open: %v", err)
			continue
		}
		if len(voucher) != 32 || s.seen(voucher) {
			continue
		}
		select {
		case s.incoming <- &Incoming{service: s, voucher: voucher}:
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Service) seen(voucher []byte) bool {
	key := hash.Sum256(voucher)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, at := range s.vouchers {
		if now.Sub(at) > voucherDedupTTL {
			delete(s.vouchers, k)
		}
	}
	if _, ok := s.vouchers[key]; ok {
		return true
	}
	s.vouchers[key] = now
	return false
}

// registrar registers with routers the service has no link with, now and
// whenever it rescans the PKI.
func (s *Service) registrar() {
	defer s.wg.Done()
	t := time.NewTicker(rescanInterval)
	defer t.Stop()
	for {
		s.registerAll()
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) registerAll() {
	nodes, err := s.ph.Services(RouterCapability)
	if err != nil {
		s.log.Warningf("listing routers: %v", err)
		return
	}
	for i := range nodes {
		node := nodes[i]
		s.mu.Lock()
		_, linked := s.links[node.NodeIDHash]
		busy := s.registering[node.NodeIDHash]
		if !linked && !busy {
			s.registering[node.NodeIDHash] = true
		}
		s.mu.Unlock()
		if linked || busy {
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.registering, node.NodeIDHash)
				s.mu.Unlock()
			}()
			ctx, cancel := context.WithTimeout(s.ctx, s.cfg.RegisterTimeout)
			defer cancel()
			conn, err := Register(ctx, s.ph, s.key, &node, s.cfg.PollInterval)
			if err != nil {
				if s.ctx.Err() == nil {
					s.log.Warningf("registering with router %x: %v", node.NodeIDHash[:8], err)
				}
				return
			}
			l := &linkState{node: node, conn: conn}
			s.mu.Lock()
			s.links[node.NodeIDHash] = l
			s.mu.Unlock()
			s.saveLink(l)
			s.startLink(l)
			s.log.Noticef("linked with router %x", node.NodeIDHash[:8])
			s.advertise()
		}()
	}
}

func (s *Service) advertise() {
	if s.cfg.Advertiser == nil {
		return
	}
	if err := s.cfg.Advertiser.Advertise(s.ctx, s.Descriptor()); err != nil && s.ctx.Err() == nil {
		s.log.Warningf("advertising: %v", err)
	}
}

// refresher rewrites recently sent boxes on links and sessions, so they
// survive replica garbage collection.
func (s *Service) refresher() {
	defer s.wg.Done()
	t := time.NewTicker(max(s.cfg.Retention/7, time.Minute))
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		conns := make([]*Conn, 0, len(s.links)+len(s.sessions))
		for _, l := range s.links {
			conns = append(conns, l.conn)
		}
		for _, sess := range s.sessions {
			conns = append(conns, sess.Conn)
		}
		s.mu.Unlock()
		for _, c := range conns {
			if err := c.Refresh(s.ctx, s.cfg.Retention); err != nil && s.ctx.Err() == nil {
				s.log.Warningf("refreshing: %v", err)
			}
		}
	}
}

// Dial connects a client to the service d describes: it mints a voucher,
// routes it sealed to the service, and waits for the service's reply.
func Dial(ctx context.Context, ph Pigeonhole, d *ServiceDescriptor, displayName string, pollInterval time.Duration) (*Conn, error) {
	pending, err := Mint(ctx, ph, displayName)
	if err != nil {
		return nil, err
	}
	if err := Route(ctx, ph, d, pending.Voucher); err != nil {
		return nil, err
	}
	return pending.Await(ctx, ph, pollInterval)
}
