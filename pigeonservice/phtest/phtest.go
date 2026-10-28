// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package phtest provides an in-memory pigeonservice.Pigeonhole for tests.
// Boxes are addressed by their real BACAP box IDs and vouchers use the real
// hpqc voucher code, so salt-mutated caps meet exactly as on the network.
package phtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/protocols/sealedbox"
	"github.com/katzenpost/hpqc/voucher"

	"github.com/katzenpost/katzenpost/pigeonservice"
)

// DefaultMaxPlaintext is the box size the network uses unless a test sets
// another.
const DefaultMaxPlaintext = 1500

// Handler serves requests to an in-memory mixnet service.
type Handler func(ctx context.Context, payload []byte) []byte

type endpoint struct {
	node [32]byte
	name string
}

type stored struct {
	plaintext []byte
	tombstone bool
}

// Network is an in-memory mixnet with Pigeonhole storage. It implements
// pigeonservice.Pigeonhole; every party in a test shares one Network.
type Network struct {
	MaxBox int

	mu       sync.Mutex
	boxes    map[[32]byte]stored
	handlers map[endpoint]Handler
	services map[string][]pigeonservice.ServiceNode
	// Repeat is how many times each request is delivered, to exercise a
	// service's handling of retransmissions.
	Repeat int
	// Writes counts box writes, tombstones included.
	Writes int
	// TombstoneGate, when set, holds every tombstone until it is closed,
	// standing in for a slow round trip through the mixnet.
	TombstoneGate chan struct{}
}

// NewNetwork returns an empty network.
func NewNetwork() *Network {
	return &Network{
		MaxBox:   DefaultMaxPlaintext,
		boxes:    make(map[[32]byte]stored),
		handlers: make(map[endpoint]Handler),
		services: make(map[string][]pigeonservice.ServiceNode),
		Repeat:   1,
	}
}

// AddService registers a mixnet service instance and its handler.
func (n *Network) AddService(capability string, node [32]byte, name string, params map[string]any, h Handler) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handlers[endpoint{node, name}] = h
	n.services[capability] = append(n.services[capability], pigeonservice.ServiceNode{
		NodeIDHash: node,
		Endpoint:   []byte(name),
		Params:     params,
	})
}

// Box reports what is stored at a box: its plaintext, whether it is a
// tombstone, and whether anything is stored at all.
func (n *Network) Box(readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex) ([]byte, bool, bool) {
	id, err := readCap.DeriveBoxID(idx)
	if err != nil {
		return nil, false, false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s, ok := n.boxes[boxKey(id.Bytes())]
	return s.plaintext, s.tombstone, ok
}

// Forget erases a box, as replica garbage collection would.
func (n *Network) Forget(readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex) {
	id, err := readCap.DeriveBoxID(idx)
	if err != nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.boxes, boxKey(id.Bytes()))
}

func (n *Network) NewStream() (*bacap.WriteCap, *bacap.ReadCap, *bacap.MessageBoxIndex, error) {
	wc, err := bacap.NewWriteCap(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	return wc, wc.ReadCap(), wc.GetMessageBoxIndex(), nil
}

func (n *Network) put(writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, s stored) error {
	id, err := writeCap.DeriveBoxID(idx)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Writes++
	key := boxKey(id.Bytes())
	if _, ok := n.boxes[key]; ok && !s.tombstone {
		// As on the network, a second write to a box is an idempotent
		// success and leaves the first in place.
		return nil
	}
	n.boxes[key] = s
	return nil
}

func (n *Network) Write(ctx context.Context, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, plaintext []byte) (*bacap.MessageBoxIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(plaintext) > n.MaxBox {
		return nil, errors.New("phtest: plaintext larger than a box")
	}
	if err := n.put(writeCap, idx, stored{plaintext: bytes.Clone(plaintext), tombstone: len(plaintext) == 0}); err != nil {
		return nil, err
	}
	return idx.NextIndex()
}

func (n *Network) Read(ctx context.Context, readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex) ([]byte, *bacap.MessageBoxIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	plaintext, tombstone, ok := n.Box(readCap, idx)
	if !ok {
		return nil, nil, pigeonservice.ErrBoxNotFound
	}
	next, err := idx.NextIndex()
	if err != nil {
		return nil, nil, err
	}
	if tombstone {
		return nil, next, pigeonservice.ErrTombstone
	}
	return bytes.Clone(plaintext), next, nil
}

func (n *Network) Tombstone(ctx context.Context, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex) error {
	if n.TombstoneGate != nil {
		select {
		case <-n.TombstoneGate:
		case <-ctx.Done():
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return n.put(writeCap, idx, stored{tombstone: true})
}

func (n *Network) WritePayload(ctx context.Context, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, payload []byte) (*bacap.MessageBoxIndex, error) {
	for len(payload) > 0 {
		chunk := payload[:min(len(payload), n.MaxBox)]
		payload = payload[len(chunk):]
		var err error
		if idx, err = n.Write(ctx, writeCap, idx, chunk); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

func (n *Network) MaxPlaintext() int {
	return n.MaxBox
}

func (n *Network) VoucherMint(messageWriteCap []byte, displayName string) (*pigeonservice.MintResult, error) {
	r, err := voucher.VoucherMint(messageWriteCap, displayName, nil)
	if err != nil {
		return nil, err
	}
	return &pigeonservice.MintResult{
		Voucher:         r.Voucher,
		Payload:         r.VoucherPayload,
		VoucherWriteCap: r.VoucherWriteCap,
		VoucherReadCap:  r.VoucherReadCap,
		SecretKey:       r.VoucherSecretKey,
	}, nil
}

func (n *Network) VoucherInduct(v, payload, whoReply []byte) (*pigeonservice.InductResult, error) {
	r, err := voucher.VoucherInduct(v, payload, whoReply, nil, nil)
	if err != nil {
		return nil, err
	}
	return &pigeonservice.InductResult{
		MutatedReadCap:  r.MutatedMessageReadCap,
		SealedReply:     r.SealedReply,
		VoucherWriteCap: r.VoucherWriteCap,
	}, nil
}

func (n *Network) VoucherOpen(secretKey, sealedReply, messageWriteCap []byte) (*pigeonservice.OpenResult, error) {
	r, err := voucher.VoucherOpenReply(secretKey, sealedReply, messageWriteCap)
	if err != nil {
		return nil, err
	}
	return &pigeonservice.OpenResult{WhoReply: r.WhoReply, MutatedWriteCap: r.MutatedMessageWriteCap}, nil
}

func (n *Network) VoucherDeriveStream(v []byte) ([]byte, []byte, error) {
	r, err := voucher.DeriveVoucherStream(v)
	if err != nil {
		return nil, nil, err
	}
	return r.VoucherWriteCap, r.VoucherReadCap, nil
}

func (n *Network) BoxSeal(nikeScheme string, publicKey, plaintext []byte) ([]byte, error) {
	scheme := schemes.ByName(nikeScheme)
	if scheme == nil {
		return nil, errors.New("phtest: unknown NIKE scheme")
	}
	pub, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return sealedbox.NewScheme(scheme).Seal(pub, plaintext)
}

func (n *Network) Request(ctx context.Context, node *[32]byte, name []byte, payload []byte) ([]byte, error) {
	n.mu.Lock()
	h, ok := n.handlers[endpoint{*node, string(name)}]
	repeat := n.Repeat
	n.mu.Unlock()
	if !ok {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var reply []byte
	for range max(repeat, 1) {
		reply = h(ctx, bytes.Clone(payload))
	}
	return reply, nil
}

func (n *Network) Services(capability string) ([]pigeonservice.ServiceNode, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]pigeonservice.ServiceNode(nil), n.services[capability]...), nil
}

func boxKey(b []byte) [32]byte {
	var k [32]byte
	copy(k[:], b)
	return k
}

var _ pigeonservice.Pigeonhole = (*Network)(nil)
