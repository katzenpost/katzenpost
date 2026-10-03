// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/internal/constants"
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

// document is a single document in an authentication snapshot. Its epoch is
// expressed as an offset from the current epoch; layer is 0 for the eligible
// direction, 1 for the wrong direction, and -1 for an identity that is absent.
// The layer is remapped per direction when the snapshot is built.
type document struct {
	offset     int
	layer, key int
}

// authCase is one snapshot scenario. switchBoundary marks a snapshot that the
// live document cache never constructs (for example a now+1 document at or past
// the slack boundary). Those cases pin the epoch/boundary logic of
// authenticateConnection and must not be read as end-to-end scenarios. Every
// other case is built exactly the way documentsForAuthentication builds the live
// snapshot, so its input is production-reachable.
type authCase struct {
	name           string
	docs           []document
	key            int
	till           time.Duration
	switchBoundary bool
	valid          bool
	incomingSend   bool
	outgoingSend   bool
}

// snapshot builds an authentication snapshot. When reachable is true it mirrors
// documentsForAuthentication: newest-first, the now+1 document only inside the
// early-connect slack window, nowDoc bound to epoch now, and past entries limited
// to the NumMixKeys window. When reachable is false the listed documents are used
// verbatim. It also returns the newest direction-eligible descriptor, which
// authenticateConnection is expected to return on success.
func (f *authFixture) snapshot(t *testing.T, now uint64, till time.Duration, outgoing, reachable bool, specs []document) ([]*pkicache.Entry, *pkicache.Entry, *cpki.MixDescriptor) {
	t.Helper()
	byOffset := make(map[int]document, len(specs))
	for _, s := range specs {
		byOffset[s.offset] = s
	}

	var offsets []int
	if reachable {
		start := 0
		if till < epochtime.Period/8 {
			start = 1
		}
		for off := start; off >= -(constants.NumMixKeys - 1); off-- {
			if _, ok := byOffset[off]; ok {
				offsets = append(offsets, off)
			}
		}
	} else {
		for _, s := range specs {
			offsets = append(offsets, s.offset)
		}
	}

	var docs []*pkicache.Entry
	var nowDoc *pkicache.Entry
	var newest *cpki.MixDescriptor
	for _, off := range offsets {
		spec := byOffset[off]
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
		entry, desc := f.entry(t, uint64(int(now)+off), layer, spec.key)
		docs = append(docs, entry)
		if off == 0 {
			nowDoc = entry
		}
		if newest == nil && spec.layer == 0 {
			newest = desc
		}
	}
	return docs, nowDoc, newest
}

func TestAuthenticateConnectionEpochsAndKeys(t *testing.T) {
	f := newAuthFixture(t)
	const now = uint64(100)
	slack := epochtime.Period / 8
	cases := []authCase{
		{name: "no documents"},
		{name: "unknown identity", docs: []document{{0, -1, 0}}},
		{name: "wrong direction", docs: []document{{0, 1, 0}}},
		{name: "current key", docs: []document{{0, 0, 0}}, valid: true, incomingSend: true, outgoingSend: true},
		{name: "unrelated key rejected", docs: []document{{0, 0, 0}}, key: 2},
		{name: "next at slack boundary", docs: []document{{1, 0, 0}}, till: slack, switchBoundary: true, valid: true},
		{name: "next before slack", docs: []document{{1, 0, 0}}, till: slack + 1, switchBoundary: true, valid: true},
		{name: "next inside slack", docs: []document{{1, 0, 0}}, till: slack - 1, valid: true, incomingSend: true},
		{name: "newest key authorizes current topology", docs: []document{{1, 0, 1}, {0, 0, 0}}, key: 1, till: slack, switchBoundary: true, valid: true, incomingSend: true, outgoingSend: true},
		{name: "newest key inside connect window authorizes current topology", docs: []document{{1, 0, 1}, {0, 0, 0}}, key: 1, till: slack - 1, valid: true, incomingSend: true, outgoingSend: true},
		{name: "newest key inside connect window authorizes past topology", docs: []document{{1, 0, 1}, {0, 1, 1}, {-1, 0, 0}}, key: 1, till: slack - 1, valid: true, incomingSend: true, outgoingSend: true},
		{name: "current key remains accepted after rotation", docs: []document{{1, 0, 1}, {0, 0, 0}}, key: 0, till: slack, switchBoundary: true, valid: true, incomingSend: true, outgoingSend: true},
		{name: "neither key matches", docs: []document{{1, 0, 1}, {0, 0, 0}}, key: 2, till: slack, switchBoundary: true},
		{name: "past without current document", docs: []document{{-1, 0, 0}}},
		{name: "past with delisted identity", docs: []document{{0, -1, 0}, {-1, 0, 0}}},
		{name: "past with identity still listed in other layer", docs: []document{{0, 1, 1}, {-1, 0, 0}}, valid: true, incomingSend: true, outgoingSend: true},
		{name: "newest eligible key authorizes past topology", docs: []document{{1, 0, 1}, {0, 1, 1}, {-1, 0, 0}}, key: 1, till: slack, switchBoundary: true, valid: true, incomingSend: true, outgoingSend: true},
		{name: "newest key cannot bypass delisting", docs: []document{{1, 0, 1}, {0, -1, 0}, {-1, 0, 0}}, key: 1, till: slack, switchBoundary: true, valid: true},
		{name: "newest key cannot bypass missing current document", docs: []document{{1, 0, 1}, {-1, 0, 0}}, key: 1, till: slack, switchBoundary: true, valid: true},
		{name: "wrong direction key is not newest eligible key", docs: []document{{1, 1, 1}, {0, 0, 0}}, key: 1, till: slack, switchBoundary: true},
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
					docs, current, newest := f.snapshot(t, now, tc.till, outgoing, !tc.switchBoundary, tc.docs)
					id := hash.Sum256(f.peerBlob)
					creds := &wire.PeerCredentials{AdditionalData: id[:], PublicKey: f.keys[tc.key]}
					desc, send, valid := f.p.authenticateConnectionWithDocs(creds, outgoing, docs, current, now, tc.till)
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

type typedNilKey struct{}

func (*typedNilKey) MarshalBinary() ([]byte, error) { return nil, errors.New("typed nil key") }
func (*typedNilKey) Scheme() kem.Scheme             { return nil }
func (*typedNilKey) Equal(kem.PublicKey) bool       { return false }

type panickingReceiverKey struct {
	payload []byte
}

func (k *panickingReceiverKey) MarshalBinary() ([]byte, error) {
	return append([]byte(nil), k.payload...), nil
}
func (k *panickingReceiverKey) Scheme() kem.Scheme       { return nil }
func (k *panickingReceiverKey) Equal(kem.PublicKey) bool { return false }

type emptyBlobKey struct{}

func (k *emptyBlobKey) MarshalBinary() ([]byte, error) { return []byte{}, nil }
func (k *emptyBlobKey) Scheme() kem.Scheme             { return nil }
func (k *emptyBlobKey) Equal(kem.PublicKey) bool       { return false }

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
		{"typed nil key", &wire.PeerCredentials{AdditionalData: id[:], PublicKey: (*typedNilKey)(nil)}, true},
		{"typed nil panicking receiver key", &wire.PeerCredentials{AdditionalData: id[:], PublicKey: (*panickingReceiverKey)(nil)}, true},
		{"empty blob key", &wire.PeerCredentials{AdditionalData: id[:], PublicKey: &emptyBlobKey{}}, true},
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
			now:     currentEntry,
			now - 1: pastEntry,
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
			now:     currentEntry,
			now - 1: pastEntry,
		}
		// Peer connects using the old key 0 from past document
		creds := &wire.PeerCredentials{AdditionalData: id[:], PublicKey: f.keys[0]}
		desc, send, valid := f.p.AuthenticateConnection(creds, false)
		if desc == nil || !send || !valid {
			t.Fatalf("retained peer with active listing should be authorized, got desc=%v send=%v valid=%v", desc, send, valid)
		}
	})
}

func TestConsensusDocumentInvalidSignature(t *testing.T) {
	ed25519 := signSchemes.ByName("Ed25519")
	authPub, authPriv, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	attackerPub, attackerPriv, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	xwing := schemes.ByName("xwing")
	attackerLinkKey, _, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	attackerLinkBlob, err := attackerLinkKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	attackerIDBlob, err := attackerPub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	now, _, _ := epochtime.Now()
	// Build a well-formed consensus document containing the attacker's descriptor.
	doc := &cpki.Document{
		Epoch:              now,
		Topology:           make([][]*cpki.MixDescriptor, 3),
		Version:            cpki.DocumentVersion,
		PKISignatureScheme: ed25519.Name(),
	}
	attackerDesc := &cpki.MixDescriptor{
		Name:        "attacker-node",
		IdentityKey: attackerIDBlob,
		LinkKey:     attackerLinkBlob,
		Epoch:       now,
		Version:     cpki.DescriptorVersion,
	}
	doc.Topology[0] = []*cpki.MixDescriptor{attackerDesc}

	t.Run("well-formed document with no signatures is rejected", func(t *testing.T) {
		rawCertified, err := doc.MarshalCertificate()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cpki.ParseDocument(rawCertified); !errors.Is(err, cpki.ErrDocumentNotSigned) {
			t.Fatalf("expected ErrDocumentNotSigned from ParseDocument, got: %v", err)
		}
		if _, err := cpki.FromPayload(authPub, rawCertified); err == nil {
			t.Fatal("expected FromPayload to fail on unsigned document, got nil")
		}
	})

	t.Run("well-formed document signed by untrusted key is rejected", func(t *testing.T) {
		signedByAttacker, err := cpki.SignDocument(attackerPriv, attackerPub, doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cpki.FromPayload(authPub, signedByAttacker); !errors.Is(err, cert.ErrIdentitySignatureNotFound) {
			t.Fatalf("expected ErrIdentitySignatureNotFound, got: %v", err)
		}
		_, _, _, err = cert.VerifyThreshold([]sign.PublicKey{authPub}, 1, signedByAttacker)
		if !errors.Is(err, cert.ErrThresholdNotMet) {
			t.Fatalf("expected ErrThresholdNotMet, got: %v", err)
		}
	})

	t.Run("well-formed document with corrupted signature is rejected", func(t *testing.T) {
		legitSigned, err := cpki.SignDocument(authPriv, authPub, doc)
		if err != nil {
			t.Fatal(err)
		}
		c := new(cert.Certificate)
		if err := cbor.Unmarshal(legitSigned, c); err != nil {
			t.Fatal(err)
		}
		for k, sig := range c.Signatures {
			sig.Payload[0] ^= 0xff
			c.Signatures[k] = sig
		}
		tampered, err := c.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		if _, err := cpki.FromPayload(authPub, tampered); !errors.Is(err, cert.ErrBadSignature) {
			t.Fatalf("expected ErrBadSignature, got: %v", err)
		}
		_, _, _, err = cert.VerifyThreshold([]sign.PublicKey{authPub}, 1, tampered)
		if !errors.Is(err, cert.ErrThresholdNotMet) {
			t.Fatalf("expected ErrThresholdNotMet, got: %v", err)
		}
	})

	t.Run("properly signed document admits the peer, unsigned cannot", func(t *testing.T) {
		f := newAuthFixture(t)
		id := hash.Sum256(attackerIDBlob)

		// A document that lists self and the attacker as an incoming peer.
		cachedDoc := &cpki.Document{
			Epoch:              now,
			Topology:           make([][]*cpki.MixDescriptor, 3),
			Version:            cpki.DocumentVersion,
			PKISignatureScheme: ed25519.Name(),
		}
		cachedDoc.Topology[1] = []*cpki.MixDescriptor{{Name: "self", IdentityKey: f.selfBlob}}
		cachedDoc.Topology[0] = []*cpki.MixDescriptor{attackerDesc}

		// Snapshot the unsigned certificate before SignDocument adds signatures.
		unsigned, err := cachedDoc.MarshalCertificate()
		if err != nil {
			t.Fatal(err)
		}
		signed, err := cpki.SignDocument(authPriv, authPub, cachedDoc)
		if err != nil {
			t.Fatal(err)
		}

		// A properly signed document parses, can be cached, and admits the peer.
		parsed, err := cpki.FromPayload(authPub, signed)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := pkicache.New(parsed, f.self, false, false)
		if err != nil {
			t.Fatal(err)
		}
		f.p.docs = map[uint64]*pkicache.Entry{now: entry}

		creds := &wire.PeerCredentials{
			AdditionalData: id[:],
			PublicKey:      attackerLinkKey,
		}
		desc, canSend, isValid := f.p.AuthenticateConnection(creds, false)
		if desc == nil || !canSend || !isValid {
			t.Fatalf("properly signed document should admit the peer: desc=%v canSend=%v isValid=%v", desc, canSend, isValid)
		}

		// The unsigned certificate is rejected before admission, so it can never
		// be cached and therefore can never authenticate a peer.
		if _, err := cpki.FromPayload(authPub, unsigned); err == nil {
			t.Fatal("expected unsigned document to be rejected at admission")
		}
	})
}
