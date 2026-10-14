// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestGatewayWithoutTCPIsAcceptedWithAWarning(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	for _, c := range []struct {
		name      string
		isGateway bool
		addresses map[string][]string
		warn      bool
	}{
		{"gateway1", true, map[string][]string{"quic": {"quic://127.0.0.1:1"}}, true},
		{"gateway1", true, map[string][]string{"quic": {"quic://127.0.0.1:1"}, "tcp4": {"tcp://127.0.0.1:1"}}, false},
		{"gateway1", true, map[string][]string{"quic": {"quic://127.0.0.1:1"}, "onion": {"onion://abc.onion:1"}}, false},
		{"mix1", false, map[string][]string{"quic": {"quic://127.0.0.1:1"}}, false},
	} {
		pub, priv, err := signschemes.ByName(testSchemeName).GenerateKey()
		require.NoError(t, err)
		idKey, err := pub.MarshalBinary()
		require.NoError(t, err)
		idHash := hash.Sum256(idKey)
		srv := quicKeyHashServer(t, testSchemeName, idHash)
		srv.state.authorizedGatewayNodes = map[[publicKeyHashSize]byte]string{idHash: "gateway1"}
		logFile := filepath.Join(t.TempDir(), "authority.log")
		backend, err := log.New(logFile, "WARNING", false)
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		srv.log = backend.GetLogger("server")

		upload := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{
			Name:          c.name,
			Epoch:         epoch,
			IdentityKey:   idKey,
			LinkKey:       []byte{1},
			MixKeys:       map[uint64][]byte{epoch: {1}},
			Addresses:     c.addresses,
			IsGatewayNode: c.isGateway,
		}}
		require.NoError(t, upload.Sign(priv, pub))
		raw, err := upload.Marshal()
		require.NoError(t, err)
		resp, ok := srv.onPostDescriptor("peer", &commands.PostDescriptor{Epoch: epoch, Payload: raw}, idHash[:], []byte{1}).(*commands.PostDescriptorStatus)
		require.True(t, ok)
		require.Equal(t, uint8(commands.DescriptorOk), resp.ErrorCode, "%s %v", c.name, c.addresses)
		logged, err := os.ReadFile(logFile)
		require.NoError(t, err)
		if c.warn {
			require.Contains(t, string(logged), "has no tcp or onion address", "%s %v", c.name, c.addresses)
		} else {
			require.NotContains(t, string(logged), "has no tcp or onion address", "%s %v", c.name, c.addresses)
		}
	}
}
