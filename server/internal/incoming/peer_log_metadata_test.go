// SPDX-License-Identifier: AGPL-3.0-only

package incoming

import (
	"container/list"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/internal/glue"
)

type rejectingPKI struct{ glue.PKI }

func (rejectingPKI) AuthenticateConnection(*wire.PeerCredentials, bool) (*pki.MixDescriptor, bool, bool) {
	return nil, false, false
}

func (rejectingPKI) CurrentDocument() (*pki.Document, error) {
	return nil, errors.New("no document")
}

type unknownClientGateway struct{ glue.Gateway }

func (unknownClientGateway) AuthenticateClient(*wire.PeerCredentials) bool { return false }

type rejectLogGlue struct {
	*capGlue
}

func (g *rejectLogGlue) PKI() glue.PKI         { return rejectingPKI{} }
func (g *rejectLogGlue) Gateway() glue.Gateway { return unknownClientGateway{} }

func TestGatewayDoesNotLogRejectedPeerIdentity(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fromClient bool
	}{
		{"client dropped from the user db", true},
		{"unknown mix", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "gateway.log")
			logBE, err := log.New(p, "DEBUG", false)
			require.NoError(t, err)
			t.Cleanup(func() { _ = logBE.Close() })
			cg := newCapGlue(t)
			cg.logBE = logBE
			l := &listener{
				glue:       &rejectLogGlue{capGlue: cg},
				log:        logBE.GetLogger("listener"),
				conns:      list.New(),
				connsByID:  make(map[[constants.RecipientIDLength]byte]*incomingConn),
				closeAllCh: make(chan interface{}),
			}
			c := &incomingConn{l: l, log: logBE.GetLogger("incoming"), fromClient: tc.fromClient}

			linkPub, _, err := benchKEMScheme.GenerateKeyPair()
			require.NoError(t, err)
			ad := make([]byte, constants.NodeIDLength)
			_, err = rand.Reader.Read(ad)
			require.NoError(t, err)
			require.False(t, c.IsPeerValid(&wire.PeerCredentials{AdditionalData: ad, PublicKey: linkPub}))

			b, err := os.ReadFile(p)
			require.NoError(t, err)
			logged := string(b)
			require.NotContains(t, logged, hex.EncodeToString(ad))
			blob, err := linkPub.MarshalBinary()
			require.NoError(t, err)
			linkHash := hash.Sum256(blob)
			require.NotContains(t, logged, hex.EncodeToString(linkHash[:]))
			pemLines := strings.Split(strings.TrimSpace(kempem.ToPublicPEMString(linkPub)), "\n")
			for _, line := range pemLines[1 : len(pemLines)-1] {
				require.NotContains(t, logged, line)
			}
		})
	}
}
