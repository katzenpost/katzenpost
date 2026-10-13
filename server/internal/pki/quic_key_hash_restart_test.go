// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

type servingPoster struct {
	quicHashPoster
	doc  *cpki.Document
	gets int
}

func (s *servingPoster) GetPKIDocumentForEpoch(_ context.Context, epoch uint64) (*cpki.Document, []byte, error) {
	s.gets++
	if s.doc != nil && epoch == s.doc.Epoch {
		return s.doc, nil, nil
	}
	return nil, nil, cpki.ErrNoDocument
}

func publishAfterRestart(t *testing.T, poster *servingPoster, idPub sign.PublicKey, idKey sign.PrivateKey) {
	t.Helper()
	quicKeys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	linkScheme := kemSchemes.ByName("xwing")
	_, link := linkScheme.DeriveKeyPair(bytes.Repeat([]byte{3}, linkScheme.SeedSize()))
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	addrs, err := makeDescAddrMap([]string{"tcp://127.0.0.1:4242", "quic://127.0.0.1:4242"})
	require.NoError(t, err)
	p := &pki{
		glue: &publishGlue{
			rotationGlue: rotationGlue{mk: &keyedMixKeys{}},
			cfg:          &config.Config{Server: &config.Server{Identifier: "mix1", PublishQUICKeyHashes: true}},
			idPub:        idPub,
			idKey:        idKey,
			link:         link,
		},
		log:           backend.GetLogger("pki"),
		impl:          poster,
		descAddrMap:   addrs,
		quicKeys:      quicKeys,
		docs:          make(map[uint64]*pkicache.Entry),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
		advertising:   true,
	}
	require.NoError(t, p.publishDescriptorIfNeeded(context.Background()))
	require.NotNil(t, poster.desc)
}

func TestRestartedQUICNodePublishesItsKeyHashWhenTheConsensusIsFetchable(t *testing.T) {
	setEpochClock(t, 1000, time.Second)
	idPub, idKey := fixedIdentityKey(t, testSchemeName)
	poster := &servingPoster{doc: heldConsensusEntry(t, heldWithAuthorityQUICKeyHashes, 1000, idPub).Document()}
	publishAfterRestart(t, poster, idPub, idKey)
	require.Len(t, poster.desc.QUICKeyHash, 3*sha256.Size, "a restarted node published its descriptor for epoch %d without its QUIC key hash; the consensus for 1000 with AuthorityQUICKeyHashes was fetchable (fetches made: %d)", poster.desc.Epoch, poster.gets)
}

func TestRestartedQUICNodeAtGenesisPublishesWithoutAKeyHash(t *testing.T) {
	setEpochClock(t, 1000, time.Second)
	idPub, idKey := fixedIdentityKey(t, testSchemeName)
	poster := &servingPoster{}
	publishAfterRestart(t, poster, idPub, idKey)
	require.Empty(t, poster.desc.QUICKeyHash)
	require.Equal(t, 1, poster.gets)
}
