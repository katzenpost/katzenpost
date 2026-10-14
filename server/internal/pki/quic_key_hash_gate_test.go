// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
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
	desc, _, _ := publishedDescriptorLogged(t, testSchemeName, []string{"tcp://127.0.0.1:4242", "quic://127.0.0.1:4242"}, authorities, t.TempDir(), "")
	return desc
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
