// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"maps"
	"slices"
	"sync"
)

type AuthorityQUICKeyPins struct {
	mu      sync.Mutex
	byEpoch map[uint64]map[[PublicKeyHashSize]byte][]byte
}

func (p *AuthorityQUICKeyPins) Learn(doc *Document) {
	if len(doc.AuthorityQUICKeyHashes) == 0 {
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
