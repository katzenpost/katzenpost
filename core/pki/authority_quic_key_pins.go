// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"maps"
	"slices"
	"sync"
)

type AuthorityQUICKeyPins struct {
	mu       sync.Mutex
	byEpoch  map[uint64]map[[PublicKeyHashSize]byte][]byte
	withheld map[uint64]bool

	mismatchEpoch uint64
	mismatched    map[[PublicKeyHashSize]byte]bool
}

func (p *AuthorityQUICKeyPins) MarkMismatch(authority [PublicKeyHashSize]byte, now uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mismatched == nil || p.mismatchEpoch != now {
		p.mismatchEpoch = now
		p.mismatched = make(map[[PublicKeyHashSize]byte]bool)
	}
	p.mismatched[authority] = true
}

func (p *AuthorityQUICKeyPins) Mismatched(authority [PublicKeyHashSize]byte, now uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mismatchEpoch == now && p.mismatched[authority]
}

func (p *AuthorityQUICKeyPins) Learn(doc *Document) {
	if len(doc.AuthorityQUICKeyHashes) == 0 {
		p.learnWithheld(doc.Epoch)
		return
	}
	entries := make(map[[PublicKeyHashSize]byte][]byte, len(doc.AuthorityQUICKeyHashes))
	for authority, quicKeyHashes := range doc.AuthorityQUICKeyHashes {
		entries[authority] = bytes.Clone(quicKeyHashes)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.byEpoch == nil {
		p.byEpoch = make(map[uint64]map[[PublicKeyHashSize]byte][]byte)
	}
	p.byEpoch[doc.Epoch] = entries
	for epoch := range p.byEpoch {
		if epoch+2 < doc.Epoch {
			delete(p.byEpoch, epoch)
		}
	}
}

func (p *AuthorityQUICKeyPins) learnWithheld(epoch uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.withheld == nil {
		p.withheld = make(map[uint64]bool)
	}
	if _, ok := p.withheld[epoch]; !ok {
		p.withheld[epoch] = false
	}
	for e := range p.withheld {
		if e+2 < epoch {
			delete(p.withheld, e)
		}
	}
}

func (p *AuthorityQUICKeyPins) FirstWithheldDial(now uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	warned, ok := p.withheld[now]
	if !ok || warned {
		return false
	}
	p.withheld[now] = true
	return true
}

func (p *AuthorityQUICKeyPins) Pins(authority [PublicKeyHashSize]byte, now uint64) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	var pins []byte
	for _, epoch := range slices.Sorted(maps.Keys(p.byEpoch)) {
		if epoch+1 < now {
			delete(p.byEpoch, epoch)
			continue
		}
		if epoch <= now+1 {
			pins = append(pins, p.byEpoch[epoch][authority]...)
		}
	}
	return pins
}
