// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
)

func TestReplicaSetFingerprintKAT(t *testing.T) {
	empty := replicaSetFingerprint(nil)
	require.Equal(t, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", hex.EncodeToString(empty[:]))

	doc := &pki.Document{StorageReplicas: []*pki.ReplicaDescriptor{{IdentityKey: []byte{2}}, {IdentityKey: []byte{1}}}}
	f := replicaSetFingerprint(doc)
	require.Equal(t, "086b2926f5e1cd1cb73847dc84aa2d90459462977cc9f7ef3c92635b728fcd82", hex.EncodeToString(f[:]))
}
