// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/url"
	"slices"
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

func (p *QUICPinMismatches) Mark(peer [sha256.Size]byte, epoch uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.peers != nil && epoch < p.epoch {
		return false
	}
	if p.peers == nil || p.epoch != epoch {
		p.epoch = epoch
		p.peers = make(map[[sha256.Size]byte]bool)
	}
	marked := !p.peers[peer]
	p.peers[peer] = true
	return marked
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

func (d *PeerDialer) unpinned(addr string) bool {
	return strings.HasPrefix(addr, "quic://") && len(d.quicKeyHashes) == 0
}

func (d *PeerDialer) dialable(addr string) bool {
	if d.unpinned(addr) {
		return false
	}
	return !d.mismatches.Has(d.peer, d.epoch) || d.opts.dialableAfterPinMismatch(addr)
}

func (d *PeerDialer) AnyDialable(addrs []string) bool {
	return slices.ContainsFunc(addrs, d.dialable)
}

func (d *PeerDialer) Dialable(addr string) bool {
	if d.unpinned(addr) {
		d.log.Debugf("peer %s: no QUIC key hash configured, not dialing %s", d.name, addr)
	}
	return d.dialable(addr)
}

func (d *PeerDialer) Dial(ctx context.Context, u *url.URL, dialFn func(ctx context.Context, network, address string) (net.Conn, error)) (net.Conn, error) {
	if u.Scheme == "quic" {
		d.log.Debugf("peer %s: quic dial pinned to its configured QUIC key hash", d.name)
	}
	conn, err := DialURL(u, ctx, dialFn, d.quicKeyHashes, d.opts)
	if errors.Is(err, ErrQUICKeyMismatch) {
		handshakeinstrument.OutgoingDialFailure("pin_mismatch")
		if d.mismatches.Mark(d.peer, d.epoch) {
			d.opts.reportPinMismatch(d.log, d.name, err)
		}
	}
	return conn, err
}
