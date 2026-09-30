// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"github.com/katzenpost/hpqc/sign"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// cert.Verify accepts only documents signed by the peer, so the only
// peer-signed documents onCertUpload sees are the peer's vote (no reveals) and
// its real certificate (reveals present). A reveal-less document uploaded as a
// certificate is therefore a vote replayed into the cert slot, and onCertUpload
// must reject it. This pins that guard and that a genuine cert still passes.
func TestOnCertUploadRejectsRevealLessDocument(t *testing.T) {
	ss := signSchemes.ByName("Ed25519")
	require.NotNil(t, ss)
	idPub, idPriv, err := ss.GenerateKey()
	require.NoError(t, err)
	pk := hash.Sum256From(idPub)

	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	votingEpoch, _, _ := epochtime.Now()

	st := &state{
		log:                   backend.GetLogger("vote-as-cert"),
		authorizedAuthorities: map[[publicKeyHashSize]byte]bool{pk: true},
		authorityNames:        map[[publicKeyHashSize]byte]string{pk: "attacker"},
		votingEpoch:           votingEpoch,
		votes: map[uint64]map[[publicKeyHashSize]byte]*pki.Document{
			votingEpoch: {pk: &pki.Document{Epoch: votingEpoch}},
		},
		certificates: map[uint64]map[[publicKeyHashSize]byte]*pki.Document{},
	}

	// A vote-shaped document for the current epoch: correctly signed, correct
	// epoch, but no SharedRandomReveal. Everything except the reveals is valid,
	// so the reveal-less guard is the only reason it can be rejected.
	doc := &pki.Document{
		Epoch:              votingEpoch,
		GenesisEpoch:       votingEpoch,
		PKISignatureScheme: ss.Name(),
	}
	signed, err := pki.SignDocument(idPriv, idPub, doc)
	require.NoError(t, err)

	resp := st.onCertUpload(&commands.Cert{
		Epoch:     votingEpoch,
		PublicKey: idPub,
		Payload:   signed,
	}, pk[:])
	status, ok := resp.(*commands.CertStatus)
	require.True(t, ok, "onCertUpload must return a *CertStatus")
	require.EqualValues(t, commands.CertNotSigned, status.ErrorCode,
		"a reveal-less document uploaded as a certificate must be rejected")
}

func TestOnCertUploadAcceptsCertWithReveals(t *testing.T) {
	ss := signSchemes.ByName("Ed25519")
	require.NotNil(t, ss)
	idPub, idPriv, err := ss.GenerateKey()
	require.NoError(t, err)
	pk := hash.Sum256From(idPub)

	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	votingEpoch, _, _ := epochtime.Now()

	st := &state{
		log:                   backend.GetLogger("vote-as-cert"),
		authorizedAuthorities: map[[publicKeyHashSize]byte]bool{pk: true},
		authorityNames:        map[[publicKeyHashSize]byte]string{pk: "honest"},
		votingEpoch:           votingEpoch,
		votes: map[uint64]map[[publicKeyHashSize]byte]*pki.Document{
			votingEpoch: {pk: &pki.Document{Epoch: votingEpoch}},
		},
		certificates: map[uint64]map[[publicKeyHashSize]byte]*pki.Document{},
	}

	// A genuine certificate for the current epoch carries at least one signed
	// shared-random reveal.
	otherPub, otherPriv, err := ss.GenerateKey()
	require.NoError(t, err)
	otherPk := hash.Sum256From(otherPub)
	st.reverseHash = map[[publicKeyHashSize]byte]sign.PublicKey{pk: idPub, otherPk: otherPub}
	st.verifiers = map[[publicKeyHashSize]byte]sign.PublicKey{pk: idPub, otherPk: otherPub}
	pair := func(priv sign.PrivateKey, pub sign.PublicKey) ([]byte, []byte) {
		sr := new(pki.SharedRandom)
		commit, err := sr.Commit(votingEpoch)
		require.NoError(t, err)
		sc, err := cert.Sign(priv, pub, commit, votingEpoch+5)
		require.NoError(t, err)
		srv, err := cert.Sign(priv, pub, sr.Reveal(), votingEpoch+5)
		require.NoError(t, err)
		return sc, srv
	}
	signedCommit, signedReveal := pair(idPriv, idPub)
	otherCommit, otherReveal := pair(otherPriv, otherPub)
	node := func(id byte, gw, svc bool) *pki.MixDescriptor {
		d := &pki.MixDescriptor{
			Name: string([]byte{'n', '0' + id}), Epoch: votingEpoch,
			IdentityKey: bytes.Repeat([]byte{id}, 32), LinkKey: bytes.Repeat([]byte{id}, 32),
			MixKeys:       map[uint64][]byte{votingEpoch: bytes.Repeat([]byte{id}, 32)},
			Addresses:     map[string][]string{"tcp": {"tcp://127.0.0.1:12345"}},
			IsGatewayNode: gw, IsServiceNode: svc,
		}
		if svc {
			d.Kaetzchen = map[string]map[string]interface{}{}
		}
		return d
	}
	doc := &pki.Document{
		Version:            pki.DocumentVersion,
		Epoch:              votingEpoch,
		GenesisEpoch:       votingEpoch,
		PKISignatureScheme: ss.Name(),
		Topology:           [][]*pki.MixDescriptor{{node(1, false, false)}},
		GatewayNodes:       []*pki.MixDescriptor{node(2, true, false)},
		ServiceNodes:       []*pki.MixDescriptor{node(3, false, true)},
		SharedRandomCommit: map[[publicKeyHashSize]byte][]byte{pk: signedCommit, otherPk: otherCommit},
		SharedRandomReveal: map[[publicKeyHashSize]byte][]byte{pk: signedReveal, otherPk: otherReveal},
	}
	signed, err := pki.SignDocument(idPriv, idPub, doc)
	require.NoError(t, err)

	resp := st.onCertUpload(&commands.Cert{
		Epoch:     votingEpoch,
		PublicKey: idPub,
		Payload:   signed,
	}, pk[:])
	status, ok := resp.(*commands.CertStatus)
	require.True(t, ok, "onCertUpload must return a *CertStatus")
	require.EqualValues(t, commands.CertOk, status.ErrorCode,
		"a certificate carrying shared-random reveals must be accepted")
}
