// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"

	dirauthconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

// recordingPKIClient records every epoch passed to GetPKIDocumentForEpoch,
// so a test can prove exactly which epochs the courier asked the dirauths for.
type recordingPKIClient struct {
	doc *pki.Document
	mu  sync.Mutex
	req []uint64
}

func (m *recordingPKIClient) GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	m.mu.Lock()
	m.req = append(m.req, epoch)
	m.mu.Unlock()
	blob, err := m.doc.MarshalCertificate()
	if err != nil {
		return nil, nil, err
	}
	return m.doc, blob, nil
}

func (m *recordingPKIClient) requested(epoch uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.req {
		if e == epoch {
			return true
		}
	}
	return false
}

func (m *recordingPKIClient) Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.MixDescriptor, loopstats *loops.LoopStats) error {
	panic(errNotImplemented)
}

func (m *recordingPKIClient) PostReplica(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.ReplicaDescriptor) error {
	panic(errNotImplemented)
}

func createTestCourierRecording(t *testing.T, rec *recordingPKIClient) *Courier {
	geo := &geo.Geometry{
		PacketLength:                3082,
		HeaderLength:                476,
		RoutingInfoLength:           410,
		PerHopRoutingInfoLength:     82,
		SURBLength:                  572,
		SphinxPlaintextHeaderLength: 2,
		PayloadTagLength:            32,
		ForwardPayloadLength:        2574,
		UserForwardPayloadLength:    2000,
		NextNodeHopLength:           65,
		SPRPKeyMaterialLength:       64,
		NIKEName:                    "X25519",
	}
	replicaSchemeName := "CTIDH1024-X25519"
	replicaScheme := schemes.ByName(replicaSchemeName)
	require.NotNil(t, replicaScheme)
	cmds := commands.NewStorageReplicaCommands(geo, replicaScheme)

	backendLog, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	server := &Server{
		cfg: &config.Config{
			SphinxGeometry: geo,
			WireKEMScheme:  "Xwing",
			PKIScheme:      "ed25519",
			EnvelopeScheme: replicaSchemeName,
			PKI: &config.PKI{
				Voting: &config.Voting{
					Authorities: []*dirauthconfig.Authority{{}},
				},
			},
		},
		logBackend: backendLog,
	}
	server.log = server.logBackend.GetLogger("courier-server")
	server.PKI, err = newPKIWorker(server, rec, server.logBackend.GetLogger("courier-pkiworker"))
	require.NoError(t, err)

	courier := NewCourier(server, cmds, replicaScheme)
	require.NotNil(t, courier)
	return courier
}

// TestStaleEnvelopeDoesNotTriggerOldEpochFetch is the empirical answer to
// "can a stale client CourierEnvelope make the courier query the dirauths for
// that old epoch?" It feeds cacheHandleCourierEnvelope a batch of envelopes
// carrying wildly out-of-window epochs and asserts that NONE of those
// client-supplied epochs is ever passed to the PKI client. The courier only
// ever fetches epochs derived from epochtime.Now(); the envelope's epoch is
// validated (and rejected) but never used to drive a fetch.
func TestStaleEnvelopeDoesNotTriggerOldEpochFetch(t *testing.T) {
	rec := &recordingPKIClient{doc: &pki.Document{Epoch: 1}}
	courier := createTestCourierRecording(t, rec)

	// Client-controlled epochs an attacker/stale client might send. These
	// are the values we must prove never reach GetPKIDocumentForEpoch.
	staleEpochs := []uint64{1, 2, 42, 238948, 239132}
	for _, e := range staleEpochs {
		env := &pigeonhole.CourierEnvelope{
			Epoch:        e,
			SenderPubkey: []byte("stale-sender-pubkey"),
			Ciphertext:   []byte("stale-ciphertext"),
		}
		reply := courier.cacheHandleCourierEnvelope(0, env)
		require.NotNil(t, reply)
		require.NotNil(t, reply.EnvelopeReply)
		require.Equal(t, pigeonhole.EnvelopeErrorInvalidEpoch, reply.EnvelopeReply.ErrorCode,
			"stale-epoch envelope (%d) must be rejected, not processed", e)
	}

	for _, e := range staleEpochs {
		require.False(t, rec.requested(e),
			"client-supplied envelope epoch %d must NEVER be requested from the dirauths", e)
	}
}
