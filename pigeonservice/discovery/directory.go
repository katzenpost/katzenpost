// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package discovery is the service directory and its client: a mixnet service holding the
// descriptors pigeonhole services advertise. It answers a lookup of one
// descriptor directly, and a request for all of them with the read cap of a
// Pigeonhole stream holding a snapshot, which it rewrites whenever a
// descriptor changes and at least once per refresh interval. A descriptor
// is a lease: the service renews it before it expires, or withdraws it,
// and the directory forgets one whose lease has passed.
package discovery

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

var (
	descriptorsBucket = []byte("descriptors")
	snapshotBucket    = []byte("snapshot")
	snapshotKey       = []byte("current")
)

// publishDelay gathers a burst of changes into one snapshot.
const publishDelay = 2 * time.Second

const (
	// MaxEntryTTL is the longest lease a directory grants a descriptor: a
	// service advertises again within it or drops out of the directory.
	MaxEntryTTL = 24 * time.Hour

	// DefaultMaxEntries is the default bound on the descriptors a directory
	// holds.
	DefaultMaxEntries = 4096
)

// Config configures a Directory.
type Config struct {
	// Key is the directory's NIKE keypair, published in the PKI.
	Key *common.PluginKey
	// DBPath is the file holding the descriptors.
	DBPath string
	// RefreshInterval is the longest a snapshot goes unrewritten. Keep it
	// well under a replica epoch so the snapshot outlives garbage
	// collection.
	RefreshInterval time.Duration
	// MaxEntries bounds the descriptors held; an advertisement of a new
	// service beyond it is refused with StatusBusy. Zero or less selects
	// DefaultMaxEntries.
	MaxEntries int
	Log        *logging.Logger
}

type entry struct {
	Descriptor common.ServiceDescriptor
	Seq        uint64
	// Expiry is when the lease ends, Unix seconds; zero once withdrawn.
	Expiry uint64
	// Keep is when the entry may be forgotten: until then it keeps the
	// Seq, so older advertisements cannot bring the descriptor back.
	Keep uint64
	// Withdrawn says the service withdrew the descriptor.
	Withdrawn bool `cbor:",omitempty"`
}

// live says the entry is a descriptor clients may see at now.
func (e *entry) live(now uint64) bool { return e != nil && !e.Withdrawn && e.Expiry > now }

// snapshotState locates a published snapshot.
type snapshotState struct {
	WriteCap []byte
	ReadCap  []byte
	Start    []byte
	Boxes    int
}

// Directory holds service descriptors.
type Directory struct {
	cfg Config
	ph  common.Pigeonhole
	db  *bolt.DB
	log *logging.Logger
	// clock judges leases; tests replace it.
	clock atomic.Pointer[func() time.Time]

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	dirty  chan struct{}

	mu       sync.Mutex
	snapshot *snapshotState
	seq      uint64
}

// New opens the directory's database and starts publishing snapshots.
func New(cfg Config, ph common.Pigeonhole) (*Directory, error) {
	if cfg.Key == nil || cfg.Log == nil {
		return nil, errors.New("directory: Key and Log are required")
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 24 * time.Hour
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	db, err := bolt.Open(cfg.DBPath, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Directory{
		cfg:    cfg,
		ph:     ph,
		db:     db,
		log:    cfg.Log,
		ctx:    ctx,
		cancel: cancel,
		dirty:  make(chan struct{}, 1),
	}
	now := time.Now
	d.clock.Store(&now)
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(descriptorsBucket); err != nil {
			return err
		}
		b, err := tx.CreateBucketIfNotExists(snapshotBucket)
		if err != nil {
			return err
		}
		if raw := b.Get(snapshotKey); raw != nil {
			var s snapshotState
			if err := common.Unmarshal(raw, &s); err != nil {
				return err
			}
			d.snapshot = &s
		}
		return nil
	})
	if err != nil {
		db.Close()
		cancel()
		return nil, err
	}
	d.wg.Add(1)
	go d.publisher()
	d.markDirty()
	return d, nil
}

func (d *Directory) now() time.Time { return (*d.clock.Load())() }

// Close stops publishing and closes the database.
func (d *Directory) Close() error {
	d.cancel()
	d.wg.Wait()
	return d.db.Close()
}

func (d *Directory) markDirty() {
	select {
	case d.dirty <- struct{}{}:
	default:
	}
}

// Handle serves one request and returns the encoded reply.
func (d *Directory) Handle(payload []byte) []byte {
	reply := d.handle(payload)
	b, err := common.Marshal(reply)
	if err != nil {
		d.log.Errorf("encoding reply: %v", err)
		return nil
	}
	return b
}

func (d *Directory) handle(payload []byte) *DirectoryReply {
	var req DirectoryRequest
	if err := common.Unmarshal(payload, &req); err != nil {
		return status(common.StatusInvalidRequest)
	}
	set := 0
	for _, p := range []bool{req.Advertise != nil, req.Withdraw != nil, req.Lookup != nil, req.List != nil} {
		if p {
			set++
		}
	}
	if set != 1 {
		return status(common.StatusInvalidRequest)
	}
	switch {
	case req.Advertise != nil:
		return d.advertise(req.Advertise)
	case req.Withdraw != nil:
		return status(d.withdraw(req.Withdraw))
	case req.Lookup != nil:
		return d.lookup(req.Lookup.ServiceID)
	default:
		return d.list()
	}
}

func status(s uint8) *DirectoryReply {
	return &DirectoryReply{Status: s}
}

func (d *Directory) get(tx *bolt.Tx, id common.ServiceID) (*entry, error) {
	raw := tx.Bucket(descriptorsBucket).Get(id[:])
	if raw == nil {
		return nil, nil
	}
	var e entry
	if err := common.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (d *Directory) advertise(req *AdvertiseRequest) *DirectoryReply {
	if err := VerifyAdvertise(d.cfg.Key, req); err != nil {
		return status(common.StatusBadMAC)
	}
	now := d.now()
	keep, ok := common.CheckLease(now, req.Expiry, MaxEntryTTL)
	if !ok {
		return status(common.StatusInvalidRequest)
	}
	id := req.Descriptor.ID()
	result := common.StatusOK
	expiry := req.Expiry
	err := d.db.Update(func(tx *bolt.Tx) error {
		old, err := d.get(tx, id)
		if err != nil {
			return err
		}
		if old != nil && old.Seq >= req.Seq {
			if old.live(uint64(now.Unix())) && old.Seq == req.Seq && sameDescriptor(&old.Descriptor, &req.Descriptor) {
				// A retransmission of the request already applied.
				expiry = old.Expiry
				return nil
			}
			result = common.StatusStale
			return nil
		}
		if !old.live(uint64(now.Unix())) {
			n, err := d.countLive(tx, uint64(now.Unix()))
			if err != nil {
				return err
			}
			if n >= d.cfg.MaxEntries {
				result = common.StatusBusy
				return nil
			}
		}
		if old != nil {
			keep = max(keep, old.Keep)
		}
		blob, err := common.Marshal(&entry{Descriptor: req.Descriptor, Seq: req.Seq, Expiry: req.Expiry, Keep: keep})
		if err != nil {
			return err
		}
		return tx.Bucket(descriptorsBucket).Put(id[:], blob)
	})
	if err != nil {
		d.log.Errorf("storing a descriptor: %v", err)
		return status(common.StatusInternalError)
	}
	if result != common.StatusOK {
		return status(result)
	}
	d.markDirty()
	return &DirectoryReply{Status: common.StatusOK, Expiry: expiry}
}

func (d *Directory) countLive(tx *bolt.Tx, now uint64) (int, error) {
	n := 0
	err := tx.Bucket(descriptorsBucket).ForEach(func(_, v []byte) error {
		var e entry
		if err := common.Unmarshal(v, &e); err != nil {
			return err
		}
		if e.live(now) {
			n++
		}
		return nil
	})
	return n, err
}

func sameDescriptor(a, b *common.ServiceDescriptor) bool {
	x, err1 := common.Marshal(a)
	y, err2 := common.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func (d *Directory) withdraw(req *WithdrawRequest) uint8 {
	result := common.StatusOK
	err := d.db.Update(func(tx *bolt.Tx) error {
		old, err := d.get(tx, req.ServiceID)
		if err != nil {
			return err
		}
		if old == nil {
			result = common.StatusUnknownService
			return nil
		}
		if err := VerifyWithdraw(d.cfg.Key, old.Descriptor.PublicKey, req); err != nil {
			result = common.StatusBadMAC
			return nil
		}
		if old.Seq >= req.Seq {
			if !old.Withdrawn || old.Seq != req.Seq {
				result = common.StatusStale
			}
			return nil
		}
		blob, err := common.Marshal(&entry{Descriptor: old.Descriptor, Seq: req.Seq, Keep: old.Keep, Withdrawn: true})
		if err != nil {
			return err
		}
		return tx.Bucket(descriptorsBucket).Put(req.ServiceID[:], blob)
	})
	if err != nil {
		d.log.Errorf("withdrawing a descriptor: %v", err)
		return common.StatusInternalError
	}
	if result == common.StatusOK {
		d.markDirty()
	}
	return result
}

func (d *Directory) lookup(id common.ServiceID) *DirectoryReply {
	var found *entry
	err := d.db.View(func(tx *bolt.Tx) error {
		var err error
		found, err = d.get(tx, id)
		return err
	})
	if err != nil {
		d.log.Errorf("looking up a descriptor: %v", err)
		return status(common.StatusInternalError)
	}
	if !found.live(uint64(d.now().Unix())) {
		return status(common.StatusUnknownService)
	}
	return &DirectoryReply{Status: common.StatusOK, Descriptor: &found.Descriptor, Expiry: found.Expiry}
}

func (d *Directory) list() *DirectoryReply {
	d.mu.Lock()
	s := d.snapshot
	d.mu.Unlock()
	if s == nil {
		return status(common.StatusBusy)
	}
	return &DirectoryReply{Status: common.StatusOK, ReadCap: s.ReadCap, StartIndex: s.Start}
}

// publisher rewrites the snapshot when descriptors change and at least once
// per refresh interval.
func (d *Directory) publisher() {
	defer d.wg.Done()
	refresh := time.NewTicker(d.cfg.RefreshInterval)
	defer refresh.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-refresh.C:
		case <-d.dirty:
			select {
			case <-time.After(publishDelay):
			case <-d.ctx.Done():
				return
			}
		}
		d.purge()
		if err := d.publish(); err != nil && d.ctx.Err() == nil {
			d.log.Errorf("publishing a snapshot: %v", err)
			d.markDirty()
		}
	}
}

// purge forgets the entries whose Keep has passed.
func (d *Directory) purge() {
	now := uint64(d.now().Unix())
	err := d.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(descriptorsBucket)
		var gone [][]byte
		err := b.ForEach(func(k, v []byte) error {
			var e entry
			if err := common.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.Keep <= now {
				gone = append(gone, bytes.Clone(k))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range gone {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		d.log.Errorf("purging descriptors: %v", err)
	}
}

func (d *Directory) descriptors() ([]common.ServiceDescriptor, error) {
	var all []common.ServiceDescriptor
	now := uint64(d.now().Unix())
	err := d.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(descriptorsBucket).ForEach(func(_, v []byte) error {
			var e entry
			if err := common.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.live(now) {
				all = append(all, e.Descriptor)
			}
			return nil
		})
	})
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i].ID(), all[j].ID()
		return bytes.Compare(a[:], b[:]) < 0
	})
	return all, err
}

// publish writes a fresh snapshot to a new stream, all at once, switches
// List to it, and tombstones the previous one.
func (d *Directory) publish() error {
	all, err := d.descriptors()
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.seq = max(d.seq+1, uint64(time.Now().UnixNano()))
	seq := d.seq
	d.mu.Unlock()
	payload, err := EncodeSnapshot(&Snapshot{Seq: seq, Descriptors: all})
	if err != nil {
		return err
	}
	wc, rc, start, err := d.ph.NewStream()
	if err != nil {
		return err
	}
	if _, err := d.ph.WritePayload(d.ctx, wc, start, payload); err != nil {
		return err
	}
	s := &snapshotState{Boxes: (len(payload) + d.ph.MaxPlaintext() - 1) / d.ph.MaxPlaintext()}
	if s.WriteCap, err = wc.MarshalBinary(); err != nil {
		return err
	}
	if s.ReadCap, err = rc.MarshalBinary(); err != nil {
		return err
	}
	if s.Start, err = start.MarshalBinary(); err != nil {
		return err
	}
	blob, err := common.Marshal(s)
	if err != nil {
		return err
	}
	if err := d.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(snapshotBucket).Put(snapshotKey, blob)
	}); err != nil {
		return err
	}

	d.mu.Lock()
	old := d.snapshot
	d.snapshot = s
	d.mu.Unlock()
	d.log.Noticef("published a snapshot of %d descriptors", len(all))
	if old != nil {
		d.tombstone(old)
	}
	return nil
}

// tombstone erases a superseded snapshot, best effort. A client that read
// its read cap just before the switch may lose the race and must ask again.
func (d *Directory) tombstone(s *snapshotState) {
	wc, err := bacap.NewWriteCapFromBytes(s.WriteCap)
	if err != nil {
		return
	}
	idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(s.Start)
	if err != nil {
		return
	}
	for range s.Boxes {
		if err := d.ph.Tombstone(d.ctx, wc, idx); err != nil {
			d.log.Warningf("tombstoning an old snapshot: %v", err)
			return
		}
		if idx, err = idx.NextIndex(); err != nil {
			return
		}
	}
}
