// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/replica/config"
)

func TestReplicaDoesNotLogPeerKeysOnFailedAuthentication(t *testing.T) {
	scheme := kemschemes.ByName("xwing")
	listedPub, _, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	peerPub, _, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	epoch, _, _ := epochtime.Now()
	doc := &pki.Document{
		Epoch: epoch,
		ServiceNodes: []*pki.MixDescriptor{{
			Name:      "servicenode1",
			Epoch:     epoch,
			Kaetzchen: map[string]map[string]interface{}{"courier": {}},
			KaetzchenAdvertizedData: map[string]map[string]interface{}{
				"courier": {"linkPublicKey": pem.ToPublicPEMString(listedPub)},
			},
		}},
	}

	t.Run("courier", func(t *testing.T) {
		c, out := courierLogConn(t, doc)
		c.l.server.cfg = &config.Config{WireKEMScheme: "xwing"}
		require.False(t, c.IsPeerValid(&wire.PeerCredentials{PublicKey: peerPub}))
		logged := out()
		requireNoPeerLinkKey(t, logged, &wire.PeerCredentials{PublicKey: listedPub})
		requireNoPeerLinkKey(t, logged, &wire.PeerCredentials{PublicKey: peerPub})
	})

	t.Run("replica", func(t *testing.T) {
		c, out := courierLogConn(t, doc)
		nodeID := make([]byte, sConstants.NodeIDLength)
		_, err := rand.Reader.Read(nodeID)
		require.NoError(t, err)
		creds := &wire.PeerCredentials{AdditionalData: nodeID, PublicKey: peerPub}
		require.False(t, c.IsPeerValid(creds))
		logged := out()
		requireNoPeerLinkKey(t, logged, creds)
		require.NotContains(t, logged, hex.EncodeToString(nodeID))
	})
}
