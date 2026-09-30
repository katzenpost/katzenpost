// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"errors"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

// authFixture builds real PKI caches with self in layer 1. A peer in layer 0
// can connect to self; a peer in layer 2 can be a destination of self.
type authFixture struct {
	self               sign.PublicKey
	selfBlob, peerBlob []byte
	keys               []kem.PublicKey
	blobs              [][]byte
	p                  *pki
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	f := &authFixture{}
	var err error
	f.self, _, err = signSchemes.ByName("Ed25519").GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f.selfBlob, err = f.self.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	peer, _, err := signSchemes.ByName("Ed25519").GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f.peerBlob, err = peer.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		key, _, err := schemes.ByName("xwing").GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		blob, err := key.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		f.keys = append(f.keys, key)
		f.blobs = append(f.blobs, blob)
	}
	backend, err := log.New("", "ERROR", true)
	if err != nil {
		t.Fatal(err)
	}
	f.p = &pki{
		log:  backend.GetLogger("auth-test"),
		docs: make(map[uint64]*pkicache.Entry),
	}
	return f
}

func (f *authFixture) entry(t *testing.T, epoch uint64, layer, key int) (*pkicache.Entry, *cpki.MixDescriptor) {
	t.Helper()
	doc := &cpki.Document{Epoch: epoch, Topology: make([][]*cpki.MixDescriptor, 3)}
	doc.Topology[1] = []*cpki.MixDescriptor{{Name: "self", IdentityKey: f.selfBlob}}
	var peer *cpki.MixDescriptor
	if layer >= 0 {
		peer = &cpki.MixDescriptor{Name: "peer", IdentityKey: f.peerBlob, LinkKey: f.blobs[key]}
		doc.Topology[layer] = append(doc.Topology[layer], peer)
	}
	entry, err := pkicache.New(doc, f.self, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return entry, peer
}

func TestAuthenticateConnectionEpochsAndKeys(t *testing.T) {
	f := newAuthFixture(t)
	const now = uint64(100)
	slack := epochtime.Period / 8
	// Snapshots at and outside slack deliberately test the policy boundary
	// independently of the document-selection cache. The inside-window cases
	// also exercise rotation with the normal next-epoch admission policy.
	// layer: 0 means the eligible direction, 1 the wrong direction, -1 absent.
	type document struct {
		offset     int
		layer, key int
	}
	cases := []struct {
		name                              string
		docs                              []document
		key                               int
		till                              time.Duration
		valid, incomingSend, outgoingSend bool
	}{
		{name: "no documents"},
		{name: "unknown identity", docs: []document{{0, -1, 0}}},
		{name: "wrong direction", docs: []document{{0, 1, 0}}},
		{name: "current key", docs: []document{{0, 0, 0}}, valid: true, incomingSend: true, outgoingSend: true},
		{name: "unrelated key rejected", docs: []document{{0, 0, 0}}, key: 2},
		{name: "next at slack boundary", docs: []document{{1, 0, 0}}, till: slack, valid: true},
		{name: "next before slack", docs: []document{{1, 0, 0}}, till: slack + 1, valid: true},
		{name: "next inside slack", docs: []document{{1, 0, 0}}, till: slack - 1, valid: true, incomingSend: true},
		{name: "newest key authorizes current topology", docs: []document{{1, 0, 1}, {0, 0, 0}}, key: 1, till: slack, valid: true, incomingSend: true, outgoingSend: true},
		{name: "newest key inside connect window authorizes current topology", docs: []document{{1, 0, 1}, {0, 0, 0}}, key: 1, till: slack - 1, valid: true, incomingSend: true, outgoingSend: true},
		{name: "newest key inside connect window authorizes past topology", docs: []document{{1, 0, 1}, {0, 1, 1}, {-1, 0, 0}}, key: 1, till: slack - 1, valid: true, incomingSend: true, outgoingSend: true},
		{name: "current key remains accepted after rotation", docs: []document{{1, 0, 1}, {0, 0, 0}}, key: 0, till: slack, valid: true, incomingSend: true, outgoingSend: true},
		{name: "neither key matches", docs: []document{{1, 0, 1}, {0, 0, 0}}, key: 2, till: slack},
		{name: "past without current document", docs: []document{{-1, 0, 0}}},
		{name: "past with delisted identity", docs: []document{{0, -1, 0}, {-1, 0, 0}}},
		{name: "past with identity still listed in other layer", docs: []document{{0, 1, 1}, {-1, 0, 0}}, valid: true, incomingSend: true, outgoingSend: true},
		{name: "newest eligible key authorizes past topology", docs: []document{{1, 0, 1}, {0, 1, 1}, {-1, 0, 0}}, key: 1, till: slack, valid: true, incomingSend: true, outgoingSend: true},
		{name: "newest key cannot bypass delisting", docs: []document{{1, 0, 1}, {0, -1, 0}, {-1, 0, 0}}, key: 1, till: slack, valid: true},
		{name: "newest key cannot bypass missing current document", docs: []document{{1, 0, 1}, {-1, 0, 0}}, key: 1, till: slack, valid: true},
		{name: "wrong direction key is not newest eligible key", docs: []document{{1, 1, 1}, {0, 0, 0}}, key: 1, till: slack},
		{name: "second past epoch is usable", docs: []document{{0, 1, 1}, {-2, 0, 0}}, valid: true, incomingSend: true, outgoingSend: true},
	}
	for _, outgoing := range []bool{false, true} {
		direction := "incoming"
		if outgoing {
			direction = "outgoing"
		}
		t.Run(direction, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					var docs []*pkicache.Entry
					var current *pkicache.Entry
					var newest *cpki.MixDescriptor
					for _, spec := range tc.docs {
						layer := spec.layer
						if layer == 0 && outgoing {
							layer = 2
						} else if layer == 1 {
							if outgoing {
								layer = 0
							} else {
								layer = 2
							}
						}
						epoch := uint64(int(now) + spec.offset)
						entry, desc := f.entry(t, epoch, layer, spec.key)
						docs = append(docs, entry)
						if epoch == now {
							current = entry
						}
						if newest == nil && spec.layer == 0 {
							newest = desc
						}
					}
					id := hash.Sum256(f.peerBlob)
					creds := &wire.PeerCredentials{AdditionalData: id[:], PublicKey: f.keys[tc.key]}
					desc, send, valid := f.p.authenticateConnection(creds, outgoing, docs, current, now, tc.till)
					wantSend := tc.incomingSend
					if outgoing {
						wantSend = tc.outgoingSend
					}
					if valid != tc.valid || send != wantSend {
						t.Fatalf("got send=%v valid=%v, want send=%v valid=%v", send, valid, wantSend, tc.valid)
					}
					if desc != newest {
						t.Fatal("did not return newest direction-eligible descriptor")
					}
				})
			}
		})
	}
}

type failingAuthKey struct{ kem.PublicKey }

func (failingAuthKey) MarshalBinary() ([]byte, error) { return nil, errors.New("test marshal failure") }

func TestAuthenticateConnectionInvalidCredentials(t *testing.T) {
	f := newAuthFixture(t)
	now, _, _ := epochtime.Now()
	entry, _ := f.entry(t, now, 0, 0)
	f.p.docs[now] = entry

	id := hash.Sum256(f.peerBlob)
	attackerKey, _, err := schemes.ByName("xwing").GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	randomID := hash.Sum256([]byte("unlisted-attacker-identity"))

	for _, tc := range []struct {
		name        string
		creds       *wire.PeerCredentials
		wantNilDesc bool
	}{
		{"nil credentials", nil, true},
		{"nil key", &wire.PeerCredentials{AdditionalData: id[:]}, true},
		{"empty identity", &wire.PeerCredentials{PublicKey: f.keys[0]}, true},
		{"short identity", &wire.PeerCredentials{AdditionalData: id[:len(id)-1], PublicKey: f.keys[0]}, true},
		{"long identity", &wire.PeerCredentials{AdditionalData: make([]byte, len(id)+1), PublicKey: f.keys[0]}, true},
		{"marshal failure", &wire.PeerCredentials{AdditionalData: id[:], PublicKey: failingAuthKey{f.keys[0]}}, true},
		{"attacker key not in consensus", &wire.PeerCredentials{AdditionalData: id[:], PublicKey: attackerKey}, false},
		{"attacker identity not in consensus", &wire.PeerCredentials{AdditionalData: randomID[:], PublicKey: f.keys[0]}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			desc, send, valid := f.p.AuthenticateConnection(tc.creds, false)
			if send || valid {
				t.Fatalf("invalid credentials authorized: send=%v valid=%v", send, valid)
			}
			if tc.wantNilDesc && desc != nil {
				t.Fatalf("expected nil descriptor, got %v", desc)
			}
		})
	}
}

func TestAuthenticateConnectionExportedMethod(t *testing.T) {
	f := newAuthFixture(t)
	now, _, _ := epochtime.Now()
	id := hash.Sum256(f.peerBlob)

	t.Run("current document positive path", func(t *testing.T) {
		entry, _ := f.entry(t, now, 0, 0)
		f.p.docs = map[uint64]*pkicache.Entry{
			now: entry,
		}
		creds := &wire.PeerCredentials{AdditionalData: id[:], PublicKey: f.keys[0]}
		desc, send, valid := f.p.AuthenticateConnection(creds, false)
		if desc == nil || !send || !valid {
			t.Fatalf("expected valid connection, got desc=%v send=%v valid=%v", desc, send, valid)
		}
	})

	t.Run("past document delisting enforcement", func(t *testing.T) {
		// Peer is listed in past document (now-1) but absent/delisted in current document (now).
		pastEntry, _ := f.entry(t, now-1, 0, 0)
		currentEntry, _ := f.entry(t, now, -1, 0) // layer -1: peer omitted from current topology
		f.p.docs = map[uint64]*pkicache.Entry{
			now:   currentEntry,
			now-1: pastEntry,
		}
		creds := &wire.PeerCredentials{AdditionalData: id[:], PublicKey: f.keys[0]}
		desc, send, valid := f.p.AuthenticateConnection(creds, false)
		if send || valid {
			t.Fatalf("delisted peer must not be authorized to send, got send=%v valid=%v", send, valid)
		}
		if desc == nil {
			t.Fatal("expected past descriptor to be returned even if delisted")
		}
	})

	t.Run("past document retained with active listing", func(t *testing.T) {
		// Peer is in past document (now-1) with old key 0, and still listed in current document (now) with rotated key 1.
		pastEntry, _ := f.entry(t, now-1, 0, 0)
		currentEntry, _ := f.entry(t, now, 0, 1)
		f.p.docs = map[uint64]*pkicache.Entry{
			now:   currentEntry,
			now-1: pastEntry,
		}
		// Peer connects using the old key 0 from past document
		creds := &wire.PeerCredentials{AdditionalData: id[:], PublicKey: f.keys[0]}
		desc, send, valid := f.p.AuthenticateConnection(creds, false)
		if desc == nil || !send || !valid {
			t.Fatalf("retained peer with active listing should be authorized, got desc=%v send=%v valid=%v", desc, send, valid)
		}
	})
}
