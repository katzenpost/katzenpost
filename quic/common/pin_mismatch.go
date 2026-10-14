// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/sha256"
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

func (o *Options) DialableAfterPinMismatch(addr string) bool {
	return strings.HasPrefix(addr, "quic://") == o.StrictPinMismatch()
}

func (o *Options) AddressesAfterPinMismatch(addrs []string) []string {
	return slices.DeleteFunc(slices.Clone(addrs), func(addr string) bool {
		return !o.DialableAfterPinMismatch(addr)
	})
}

func (o *Options) ReportPinMismatch(log *logging.Logger, peer string, err error) {
	handshakeinstrument.OutgoingDialFailure("pin_mismatch")
	if o.StrictPinMismatch() {
		log.Warningf("peer %s: %v; PinMismatch is strict, so it is dialed over quic only for the rest of this epoch", peer, err)
		return
	}
	log.Warningf("peer %s: %v; no quic to it for the rest of this epoch, falling back to tcp", peer, err)
}
