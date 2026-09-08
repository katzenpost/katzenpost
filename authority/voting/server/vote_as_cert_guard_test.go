// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
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
	})
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
	signedReveal, err := cert.Sign(idPriv, idPub, []byte("reveal"), votingEpoch+5)
	require.NoError(t, err)
	doc := &pki.Document{
		Epoch:              votingEpoch,
		GenesisEpoch:       votingEpoch,
		PKISignatureScheme: ss.Name(),
		SharedRandomReveal: map[[publicKeyHashSize]byte][]byte{pk: signedReveal},
	}
	signed, err := pki.SignDocument(idPriv, idPub, doc)
	require.NoError(t, err)

	resp := st.onCertUpload(&commands.Cert{
		Epoch:     votingEpoch,
		PublicKey: idPub,
		Payload:   signed,
	})
	status, ok := resp.(*commands.CertStatus)
	require.True(t, ok, "onCertUpload must return a *CertStatus")
	require.EqualValues(t, commands.CertOk, status.ErrorCode,
		"a certificate carrying shared-random reveals must be accepted")
}
