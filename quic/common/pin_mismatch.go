// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/wire/handshakeinstrument"
)

type QUICPinMismatches struct {
	mu    sync.Mutex
	epoch uint64
	peers map[[sha256.Size]byte]bool
}

func (p *QUICPinMismatches) Mark(peer [sha256.Size]byte, epoch uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.peers != nil && epoch < p.epoch {
		return
	}
	if p.peers == nil || p.epoch != epoch {
		p.epoch = epoch
		p.peers = make(map[[sha256.Size]byte]bool)
	}
	p.peers[peer] = true
}

func (p *QUICPinMismatches) Has(peer [sha256.Size]byte, epoch uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.epoch == epoch && p.peers[peer]
}

func (o *Options) StrictPinMismatch() bool {
	return o != nil && o.PinMismatch == PinMismatchStrict
}

func (o *Options) dialableAfterPinMismatch(addr string) bool {
	return strings.HasPrefix(addr, "quic://") == o.StrictPinMismatch()
}

func (o *Options) reportPinMismatch(log *logging.Logger, peer string, err error) {
	handshakeinstrument.OutgoingDialFailure("pin_mismatch")
	if o.StrictPinMismatch() {
		log.Warningf("peer %s: %v; PinMismatch is strict, so it is dialed over quic only for the rest of this epoch", peer, err)
		return
	}
	log.Warningf("peer %s: %v; no quic to it for the rest of this epoch, falling back to tcp", peer, err)
}

type PeerDialer struct {
	opts          *Options
	mismatches    *QUICPinMismatches
	peer          [sha256.Size]byte
	epoch         uint64
	quicKeyHashes []byte
	log           *logging.Logger
	name          string
}

func (o *Options) PeerDialer(mismatches *QUICPinMismatches, peer [sha256.Size]byte, quicKeyHashes []byte, log *logging.Logger, name string) *PeerDialer {
	return &PeerDialer{
		opts:          o,
		mismatches:    mismatches,
		peer:          peer,
		epoch:         CurrentEpoch(),
		quicKeyHashes: quicKeyHashes,
		log:           log,
		name:          name,
	}
}

func (d *PeerDialer) Dialable(addr string) bool {
	return !d.mismatches.Has(d.peer, d.epoch) || d.opts.dialableAfterPinMismatch(addr)
}

func (d *PeerDialer) Dial(ctx context.Context, u *url.URL, dialFn func(ctx context.Context, network, address string) (net.Conn, error)) (net.Conn, error) {
	conn, err := DialURL(u, ctx, dialFn, d.quicKeyHashes, d.opts)
	if errors.Is(err, ErrQUICKeyMismatch) {
		d.mismatches.Mark(d.peer, d.epoch)
		d.opts.reportPinMismatch(d.log, d.name, err)
	}
	return conn, err
}
