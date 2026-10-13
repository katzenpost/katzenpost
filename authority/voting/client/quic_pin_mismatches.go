// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"sync"

	"github.com/katzenpost/katzenpost/core/pki"
)

type quicPinMismatches struct {
	mu         sync.Mutex
	epoch      uint64
	mismatched map[[pki.PublicKeyHashSize]byte]bool
}

func (p *quicPinMismatches) mark(authority [pki.PublicKeyHashSize]byte, now uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mismatched == nil || p.epoch != now {
		p.epoch = now
		p.mismatched = make(map[[pki.PublicKeyHashSize]byte]bool)
	}
	p.mismatched[authority] = true
}

func (p *quicPinMismatches) has(authority [pki.PublicKeyHashSize]byte, now uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.epoch == now && p.mismatched[authority]
}
