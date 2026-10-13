// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/quic/common"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

var (
	tcpOnlySignedBlobSum256 = map[string]string{
		"Ed25519":          "16a9a0f6cf5c211e85b67e7892d921d6fdd2d4753257d497b9f44b0f830a88a4",
		"Ed25519 Sphincs+": "9585077c26768e783cf4fb62a6006cea1d1145fab4ae7a099c5c35d96b543966",
	}
)

type quicHashPoster struct{ desc *cpki.MixDescriptor }

func (c *quicHashPoster) GetPKIDocumentForEpoch(context.Context, uint64) (*cpki.Document, []byte, error) {
	return nil, nil, cpki.ErrNoDocument
}

func (c *quicHashPoster) Post(_ context.Context, _ uint64, _ sign.PrivateKey, _ sign.PublicKey, desc *cpki.MixDescriptor, _ *loops.LoopStats) error {
	c.desc = desc
	return nil
}

func fixedIdentityKey(t *testing.T, schemeName string) (sign.PublicKey, sign.PrivateKey) {
	t.Helper()
	scheme := signSchemes.ByName(schemeName)
	edKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	identityPublicKey, err := scheme.UnmarshalBinaryPublicKey(append([]byte(edKey.Public().(ed25519.PublicKey)), bytes.Repeat([]byte{9}, scheme.PublicKeySize()-ed25519.PublicKeySize)...))
	require.NoError(t, err)
	identityPrivateKey, err := scheme.UnmarshalBinaryPrivateKey(append([]byte(edKey), bytes.Repeat([]byte{9}, scheme.PrivateKeySize()-ed25519.PrivateKeySize)...))
	require.NoError(t, err)
	return identityPublicKey, identityPrivateKey
}

func publishedDescriptor(t *testing.T, schemeName string, addresses []string, publishQUICKeyHashes bool) *cpki.MixDescriptor {
	t.Helper()
	desc, _ := publishedDescriptorAndKeys(t, schemeName, addresses, publishQUICKeyHashes)
	return desc
}

func publishedDescriptorAndKeys(t *testing.T, schemeName string, addresses []string, publishQUICKeyHashes bool) (*cpki.MixDescriptor, *common.EpochKeys) {
	t.Helper()
	desc, quicKeys, _ := publishedDescriptorLogged(t, schemeName, addresses, publishQUICKeyHashes, t.TempDir(), "", heldWithAuthorityQUICKeyHashes)
	return desc, quicKeys
}

type heldConsensus int

const (
	heldNothing heldConsensus = iota
	heldWithoutAuthorityQUICKeyHashes
	heldWithAuthorityQUICKeyHashes
)

func heldConsensusEntry(t *testing.T, held heldConsensus, epoch uint64, idPub sign.PublicKey) *pkicache.Entry {
	t.Helper()
	idPubBlob, err := idPub.MarshalBinary()
	require.NoError(t, err)
	doc := &cpki.Document{Epoch: epoch, Topology: [][]*cpki.MixDescriptor{{{Name: "mix1", IdentityKey: idPubBlob}}}}
	if held == heldWithAuthorityQUICKeyHashes {
		doc.AuthorityQUICKeyHashes = map[[cpki.PublicKeyHashSize]byte][]byte{{1}: bytes.Repeat([]byte{2}, 3*cpki.QUICKeyHashSize)}
	}
	entry, err := pkicache.New(doc, idPub, false, false)
	require.NoError(t, err)
	return entry
}

func publishedDescriptorLogged(t *testing.T, schemeName string, addresses []string, publishQUICKeyHashes bool, quicKeyDir, logFile string, held heldConsensus) (*cpki.MixDescriptor, *common.EpochKeys, *log.Backend) {
	t.Helper()
	setEpochClock(t, 1000, time.Second)
	quicKeys, err := common.NewEpochKeys(quicKeyDir, common.CurrentEpoch)
	require.NoError(t, err)
	idPub, idKey := fixedIdentityKey(t, schemeName)
	linkScheme := kemSchemes.ByName("xwing")
	_, link := linkScheme.DeriveKeyPair(bytes.Repeat([]byte{3}, linkScheme.SeedSize()))
	level := "ERROR"
	if logFile != "" {
		level = "DEBUG"
	}
	backend, err := log.New(logFile, level, false)
	require.NoError(t, err)
	addrs, err := makeDescAddrMap(addresses)
	require.NoError(t, err)
	poster := &quicHashPoster{}
	docs := make(map[uint64]*pkicache.Entry)
	if held != heldNothing {
		docs[1000] = heldConsensusEntry(t, held, 1000, idPub)
	}
	p := &pki{
		glue: &publishGlue{
			rotationGlue: rotationGlue{mk: &keyedMixKeys{}},
			cfg:          &config.Config{Server: &config.Server{Identifier: "mix1", PublishQUICKeyHashes: publishQUICKeyHashes}},
			idPub:        idPub,
			idKey:        idKey,
			link:         link,
		},
		log:           backend.GetLogger("pki"),
		impl:          poster,
		descAddrMap:   addrs,
		quicKeys:      quicKeys,
		docs:          docs,
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
		advertising:   true,
	}
	require.NoError(t, p.publishDescriptorIfNeeded(context.Background()))
	require.NotNil(t, poster.desc)
	return poster.desc, quicKeys, backend
}

func presentedSPKI(t *testing.T, identityPrivateKey sign.PrivateKey, quicKeys *common.EpochKeys) []byte {
	t.Helper()
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, quicKeys)
	require.NoError(t, err)
	defer l.Close()
	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := common.DialURL(u, ctx, nil, nil)
	require.NoError(t, err)
	defer conn.Close()
	return conn.(*common.QuicConn).Conn.ConnectionState().TLS.PeerCertificates[0].RawSubjectPublicKeyInfo
}

func TestTCPOnlyDescriptorIsUnchanged(t *testing.T) {
	for _, scheme := range []string{"Ed25519", testSchemeName} {
		desc := publishedDescriptor(t, scheme, []string{"tcp://127.0.0.1:4242"}, true)
		require.Nil(t, desc.QUICKeyHash)
		blob, err := (&cpki.SignedUpload{MixDescriptor: desc}).Marshal()
		require.NoError(t, err)
		sum := sha256.Sum256(blob)
		require.Equal(t, tcpOnlySignedBlobSum256[scheme], hex.EncodeToString(sum[:]), scheme)
	}
}

func TestQUICNodePublishesItsKeyHash(t *testing.T) {
	for _, scheme := range []string{"Ed25519", testSchemeName} {
		desc, quicKeys := publishedDescriptorAndKeys(t, scheme, []string{"tcp://127.0.0.1:4242", "quic://127.0.0.1:4242"}, true)
		_, idKey := fixedIdentityKey(t, scheme)
		presented := sha256.Sum256(presentedSPKI(t, idKey, quicKeys))
		require.Len(t, desc.QUICKeyHash, 3*sha256.Size, scheme)
		require.Equal(t, presented[:], desc.QUICKeyHash[:sha256.Size], "%s: the listener in epoch %d must present the first key the descriptor for %d publishes", scheme, desc.Epoch-1, desc.Epoch)
	}
}

func TestQUICNodePublishesNoKeyHashByDefault(t *testing.T) {
	for _, scheme := range []string{"Ed25519", testSchemeName} {
		desc := publishedDescriptor(t, scheme, []string{"tcp://127.0.0.1:4242", "quic://127.0.0.1:4242"}, false)
		require.Nil(t, desc.QUICKeyHash, "%s: a node published its QUIC key hash without PublishQUICKeyHashes", scheme)
	}
}

func TestQUICNodePublishesThreeEpochKeyHashes(t *testing.T) {
	for _, scheme := range []string{"Ed25519", testSchemeName} {
		desc := publishedDescriptor(t, scheme, []string{"tcp://127.0.0.1:4242", "quic://127.0.0.1:4242"}, true)
		require.Len(t, desc.QUICKeyHash, 3*sha256.Size, "%s: the descriptor for epoch %d must carry the hashes of the keys for %d, %d and %d", scheme, desc.Epoch, desc.Epoch-1, desc.Epoch, desc.Epoch+1)
	}
}

func TestQUICKeysAreNeverLogged(t *testing.T) {
	quicKeyDir := t.TempDir()
	logFile := filepath.Join(t.TempDir(), "pki.log")
	_, quicKeys, backend := publishedDescriptorLogged(t, testSchemeName, []string{"quic://127.0.0.1:4242"}, true, quicKeyDir, logFile, heldWithAuthorityQUICKeyHashes)
	_, idKey := fixedIdentityKey(t, testSchemeName)
	presentedSPKI(t, idKey, quicKeys)
	backend.Close()
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.NotEmpty(t, logged)
	seeds, err := filepath.Glob(filepath.Join(quicKeyDir, "quic-tls-*.key"))
	require.NoError(t, err)
	require.Len(t, seeds, 3)
	for _, f := range seeds {
		seed, err := os.ReadFile(f)
		require.NoError(t, err)
		tlsPrivateKey := ed25519.NewKeyFromSeed(seed)
		for _, secret := range [][]byte{seed, tlsPrivateKey} {
			for _, form := range []string{hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret), fmt.Sprintf("%v", secret), string(secret)} {
				require.NotContains(t, string(logged), form, "a QUIC TLS key reached the log")
			}
		}
	}
}

func TestQUICNodePublishesKeyHashOnlyUnderAConsensusWithAuthorityHashes(t *testing.T) {
	for _, held := range []heldConsensus{heldNothing, heldWithoutAuthorityQUICKeyHashes} {
		desc, _, _ := publishedDescriptorLogged(t, testSchemeName, []string{"tcp://127.0.0.1:4242", "quic://127.0.0.1:4242"}, true, t.TempDir(), "", held)
		require.Nil(t, desc.QUICKeyHash, "held consensus %d: a node published its QUIC key hash without a consensus proving every authority current", held)
	}
}
