// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

func authoritiesWithQUICKeyHashes(total, withHash int) []*vConfig.Authority {
	authorities := make([]*vConfig.Authority, total)
	for i := range authorities {
		authorities[i] = &vConfig.Authority{Identifier: fmt.Sprintf("auth%d", i+1)}
		if i < withHash {
			authorities[i].QUICKeyHash = bytes.Repeat([]byte{byte(i + 1)}, cpki.QUICKeyHashSize)
		}
	}
	return authorities
}

func publishedDescriptorUnder(t *testing.T, authorities []*vConfig.Authority) *cpki.MixDescriptor {
	t.Helper()
	setEpochClock(t, 1000, time.Second)
	quicKeys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	idPub, idKey := fixedIdentityKey(t, testSchemeName)
	linkScheme := kemSchemes.ByName("xwing")
	_, link := linkScheme.DeriveKeyPair(bytes.Repeat([]byte{3}, linkScheme.SeedSize()))
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	addrs, err := makeDescAddrMap([]string{"tcp://127.0.0.1:4242", "quic://127.0.0.1:4242"})
	require.NoError(t, err)
	poster := &quicHashPoster{}
	p := &pki{
		glue: &publishGlue{
			rotationGlue: rotationGlue{mk: &keyedMixKeys{}},
			cfg: &config.Config{
				Server: &config.Server{Identifier: "mix1"},
				PKI:    &config.PKI{Voting: &config.Voting{Authorities: authorities}},
			},
			idPub: idPub,
			idKey: idKey,
			link:  link,
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
	return poster.desc
}

func TestQUICNodePublishesItsKeyHashWhenEveryAuthorityHasOne(t *testing.T) {
	desc := publishedDescriptorUnder(t, authoritiesWithQUICKeyHashes(3, 3))
	require.Len(t, desc.QUICKeyHash, 3*sha256.Size, "a node withheld its QUIC key hash though every authority has a QUICKeyHash")
}

func TestQUICNodeWithholdsItsKeyHashUnlessEveryAuthorityHasOne(t *testing.T) {
	for _, withHash := range []int{0, 2} {
		desc := publishedDescriptorUnder(t, authoritiesWithQUICKeyHashes(3, withHash))
		require.Nil(t, desc.QUICKeyHash, "a node published its QUIC key hash with %d of 3 authorities pinned", withHash)
	}
	desc := publishedDescriptorUnder(t, nil)
	require.Nil(t, desc.QUICKeyHash, "a node published its QUIC key hash with no authorities configured")
}
