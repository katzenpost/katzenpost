// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/quic/common"
)

type acceptAnyPeer struct{}

func (acceptAnyPeer) IsPeerValid(*wire.PeerCredentials) bool { return true }

type quicAuthorityKeys struct {
	identityPrivateKey sign.PrivateKey
	identityPublicKey  sign.PublicKey
	linkPrivateKey     kem.PrivateKey
	geo                *geo.Geometry
}

func newQUICAuthorityKeys(t *testing.T) *quicAuthorityKeys {
	t.Helper()
	identityPublicKey, identityPrivateKey, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	_, linkPrivateKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	return &quicAuthorityKeys{
		identityPrivateKey: identityPrivateKey,
		identityPublicKey:  identityPublicKey,
		linkPrivateKey:     linkPrivateKey,
		geo:                geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5),
	}
}

func (a *quicAuthorityKeys) consensus(t *testing.T, epoch uint64, quicKeyHashes []byte) []byte {
	t.Helper()
	doc, err := generateMixnet(6, 2, epoch)
	require.NoError(t, err)
	doc.AuthorityQUICKeyHashes = map[[pki.PublicKeyHashSize]byte][]byte{hash.Sum256From(a.identityPublicKey): quicKeyHashes}
	raw, err := multiSignTestDocument([]sign.PrivateKey{a.identityPrivateKey}, []sign.PublicKey{a.identityPublicKey}, doc)
	require.NoError(t, err)
	return raw
}

func (a *quicAuthorityKeys) serve(t *testing.T, keys *common.EpochKeys, consensus []byte) string {
	t.Helper()
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", a.identityPrivateKey, keys)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go a.answer(conn, consensus)
		}
	}()
	return "quic://" + l.Addr().String()
}

func (a *quicAuthorityKeys) answer(conn net.Conn, consensus []byte) {
	defer conn.Close()
	identityHash := hash.Sum256From(a.identityPublicKey)
	session, err := wire.NewPKISession(&wire.SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          a.geo,
		Authenticator:     acceptAnyPeer{},
		AdditionalData:    identityHash[:],
		AuthenticationKey: a.linkPrivateKey,
		RandomReader:      rand.Reader,
	}, false)
	if err != nil {
		return
	}
	defer session.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := session.Initialize(ctx, conn); err != nil {
		return
	}
	if _, err := session.RecvCommand(ctx); err != nil {
		return
	}
	_ = session.SendCommand(ctx, &commands.Consensus{ErrorCode: commands.ConsensusOk, Payload: consensus})
}

func (a *quicAuthorityKeys) client(t *testing.T, logFile string) (*Client, *config.Authority) {
	t.Helper()
	backend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	peer := &config.Authority{
		Identifier:        "auth1",
		WireKEMScheme:     testingSchemeName,
		IdentityPublicKey: a.identityPublicKey,
		LinkPublicKey:     config.LinkPublicKey{PublicKey: a.linkPrivateKey.Public()},
	}
	c, err := New(&Config{
		KEMScheme:          testingScheme,
		PKISignatureScheme: signSchemes.ByName(testSchemeName),
		LogBackend:         backend,
		Authorities:        []*config.Authority{peer},
		Geo:                a.geo,
		DialTimeoutSec:     5,
		RetryMaxAttempts:   1,
		RetryBaseDelay:     time.Millisecond,
		RetryMaxDelay:      time.Millisecond,
	})
	require.NoError(t, err)
	return c.(*Client), peer
}

func fetch(t *testing.T, c *Client, epoch uint64) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _, err := c.GetPKIDocumentForEpoch(ctx, epoch)
	return err
}

func TestAuthorityDialIsPinnedOnceAConsensusNamesItsKeys(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	genuineKeys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	published, err := genuineKeys.Hashes(epoch)
	require.NoError(t, err)
	impostorKeys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	_, err = impostorKeys.Hashes(epoch)
	require.NoError(t, err)
	consensus := a.consensus(t, epoch, published)
	genuine := a.serve(t, genuineKeys, consensus)
	impostor := a.serve(t, impostorKeys, consensus)

	logFile := filepath.Join(t.TempDir(), "client.log")
	c, peer := a.client(t, logFile)
	peer.Addresses = []string{impostor}
	require.NoError(t, fetch(t, c, epoch), "a bootstrap dial with no consensus must succeed unpinned")

	peer.Addresses = []string{genuine}
	require.NoError(t, fetch(t, c, epoch), "a dial to the key the consensus names must succeed")

	peer.Addresses = []string{impostor}
	require.Error(t, fetch(t, c, epoch), "a quic dial accepted a key the consensus does not name")

	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(logged), "peer auth1: quic dial unpinned, no QUIC key hashes known")
	require.Contains(t, string(logged), "peer auth1: quic dial pinned to 3 consensus QUIC key hashes")
}
