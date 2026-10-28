// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package directory is the service directory: a mixnet service holding the
// descriptors pigeonhole services advertise. It answers a lookup of one
// descriptor directly, and a request for all of them with the read cap of a
// Pigeonhole stream holding a snapshot, which it rewrites whenever a
// descriptor changes and at least once per refresh interval.
package directory

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"

	ps "github.com/katzenpost/katzenpost/pigeonservice"
)

var (
	descriptorsBucket = []byte("descriptors")
	snapshotBucket    = []byte("snapshot")
	snapshotKey       = []byte("current")
)

// publishDelay gathers a burst of changes into one snapshot.
const publishDelay = 2 * time.Second

// Config configures a Directory.
type Config struct {
	// Key is the directory's NIKE keypair, published in the PKI.
	Key *ps.PluginKey
	// DBPath is the file holding the descriptors.
	DBPath string
	// RefreshInterval is the longest a snapshot goes unrewritten. Keep it
	// well under a replica epoch so the snapshot outlives garbage
	// collection.
	RefreshInterval time.Duration
	Log             *logging.Logger
}

type entry struct {
	Descriptor ps.ServiceDescriptor
	Seq        uint64
}

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
	ph  ps.Pigeonhole
	db  *bolt.DB
	log *logging.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	dirty  chan struct{}

	mu       sync.Mutex
	snapshot *snapshotState
	seq      uint64
}

// New opens the directory's database and starts publishing snapshots.
func New(cfg Config, ph ps.Pigeonhole) (*Directory, error) {
	if cfg.Key == nil || cfg.Log == nil {
		return nil, errors.New("directory: Key and Log are required")
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 24 * time.Hour
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
			if err := ps.Unmarshal(raw, &s); err != nil {
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
	b, err := ps.Marshal(reply)
	if err != nil {
		d.log.Errorf("encoding reply: %v", err)
		return nil
	}
	return b
}

func (d *Directory) handle(payload []byte) *ps.DirectoryReply {
	var req ps.DirectoryRequest
	if err := ps.Unmarshal(payload, &req); err != nil {
		return status(ps.StatusInvalidRequest)
	}
	set := 0
	for _, p := range []bool{req.Advertise != nil, req.Withdraw != nil, req.Lookup != nil, req.List != nil} {
		if p {
			set++
		}
	}
	if set != 1 {
		return status(ps.StatusInvalidRequest)
	}
	switch {
	case req.Advertise != nil:
		return status(d.advertise(req.Advertise))
	case req.Withdraw != nil:
		return status(d.withdraw(req.Withdraw))
	case req.Lookup != nil:
		return d.lookup(req.Lookup.ServiceID)
	default:
		return d.list()
	}
}

func status(s uint8) *ps.DirectoryReply {
	return &ps.DirectoryReply{Status: s}
}

func (d *Directory) get(tx *bolt.Tx, id ps.ServiceID) (*entry, error) {
	raw := tx.Bucket(descriptorsBucket).Get(id[:])
	if raw == nil {
		return nil, nil
	}
	var e entry
	if err := ps.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (d *Directory) advertise(req *ps.AdvertiseRequest) uint8 {
	if err := d.cfg.Key.VerifyAdvertise(req); err != nil {
		return ps.StatusBadMAC
	}
	id := req.Descriptor.ID()
	result := ps.StatusOK
	err := d.db.Update(func(tx *bolt.Tx) error {
		old, err := d.get(tx, id)
		if err != nil {
			return err
		}
		if old != nil && old.Seq >= req.Seq {
			if old.Seq == req.Seq && sameDescriptor(&old.Descriptor, &req.Descriptor) {
				// A retransmission of the request already applied.
				return nil
			}
			result = ps.StatusStale
			return nil
		}
		blob, err := ps.Marshal(&entry{Descriptor: req.Descriptor, Seq: req.Seq})
		if err != nil {
			return err
		}
		return tx.Bucket(descriptorsBucket).Put(id[:], blob)
	})
	if err != nil {
		d.log.Errorf("storing a descriptor: %v", err)
		return ps.StatusInternalError
	}
	if result == ps.StatusOK {
		d.markDirty()
	}
	return result
}

func sameDescriptor(a, b *ps.ServiceDescriptor) bool {
	x, err1 := ps.Marshal(a)
	y, err2 := ps.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func (d *Directory) withdraw(req *ps.WithdrawRequest) uint8 {
	result := ps.StatusOK
	err := d.db.Update(func(tx *bolt.Tx) error {
		old, err := d.get(tx, req.ServiceID)
		if err != nil {
			return err
		}
		if old == nil {
			result = ps.StatusUnknownService
			return nil
		}
		if err := d.cfg.Key.VerifyWithdraw(old.Descriptor.PublicKey, req); err != nil {
			result = ps.StatusBadMAC
			return nil
		}
		if old.Seq >= req.Seq {
			result = ps.StatusStale
			return nil
		}
		return tx.Bucket(descriptorsBucket).Delete(req.ServiceID[:])
	})
	if err != nil {
		d.log.Errorf("withdrawing a descriptor: %v", err)
		return ps.StatusInternalError
	}
	if result == ps.StatusOK {
		d.markDirty()
	}
	return result
}

func (d *Directory) lookup(id ps.ServiceID) *ps.DirectoryReply {
	var found *entry
	err := d.db.View(func(tx *bolt.Tx) error {
		var err error
		found, err = d.get(tx, id)
		return err
	})
	if err != nil {
		d.log.Errorf("looking up a descriptor: %v", err)
		return status(ps.StatusInternalError)
	}
	if found == nil {
		return status(ps.StatusUnknownService)
	}
	return &ps.DirectoryReply{Status: ps.StatusOK, Descriptor: &found.Descriptor}
}

func (d *Directory) list() *ps.DirectoryReply {
	d.mu.Lock()
	s := d.snapshot
	d.mu.Unlock()
	if s == nil {
		return status(ps.StatusBusy)
	}
	return &ps.DirectoryReply{Status: ps.StatusOK, ReadCap: s.ReadCap, StartIndex: s.Start}
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
		if err := d.publish(); err != nil && d.ctx.Err() == nil {
			d.log.Errorf("publishing a snapshot: %v", err)
			d.markDirty()
		}
	}
}

func (d *Directory) descriptors() ([]ps.ServiceDescriptor, error) {
	var all []ps.ServiceDescriptor
	err := d.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(descriptorsBucket).ForEach(func(_, v []byte) error {
			var e entry
			if err := ps.Unmarshal(v, &e); err != nil {
				return err
			}
			all = append(all, e.Descriptor)
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
	payload, err := ps.EncodeSnapshot(&ps.Snapshot{Seq: seq, Descriptors: all})
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
	blob, err := ps.Marshal(s)
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
