// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// onCertUpload must bind the certificate's declared PublicKey to the
// wire-authenticated peer. A certificate whose PublicKey is a different
// authorized authority than the connected peer is rejected, so an authorized but
// byzantine authority cannot relay another authority's certificate on its own
// connection.
func TestOnCertUploadRejectsForeignPeerKey(t *testing.T) {
	ss := signSchemes.ByName("Ed25519")
	require.NotNil(t, ss)

	// Two distinct, both-authorized authorities: the connected peer and the
	// authority whose key the uploaded certificate declares.
	peerPub, _, err := ss.GenerateKey()
	require.NoError(t, err)
	otherPub, otherPriv, err := ss.GenerateKey()
	require.NoError(t, err)

	peerHash := hash.Sum256From(peerPub)
	otherHash := hash.Sum256From(otherPub)

	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)

	votingEpoch, _, _ := epochtime.Now()

	st := &state{
		log: backend.GetLogger("cert-peer-bind"),
		authorizedAuthorities: map[[publicKeyHashSize]byte]bool{
			peerHash:  true,
			otherHash: true,
		},
		authorityNames: map[[publicKeyHashSize]byte]string{
			peerHash:  "peer",
			otherHash: "other",
		},
		votingEpoch:  votingEpoch,
		votes:        map[uint64]map[[publicKeyHashSize]byte]*pki.Document{},
		certificates: map[uint64]map[[publicKeyHashSize]byte]*pki.Document{},
	}

	// A genuine certificate signed by the other authority for this epoch.
	doc := &pki.Document{
		Epoch:              votingEpoch,
		GenesisEpoch:       votingEpoch,
		PKISignatureScheme: ss.Name(),
	}
	signed, err := pki.SignDocument(otherPriv, otherPub, doc)
	require.NoError(t, err)

	// Uploaded over the peer's connection: the certificate declares the other
	// authority's key, which does not match the connected peer identity.
	resp := st.onCertUpload(&commands.Cert{
		Epoch:     votingEpoch,
		PublicKey: otherPub,
		Payload:   signed,
	}, peerHash[:])
	status, ok := resp.(*commands.CertStatus)
	require.True(t, ok, "onCertUpload must return a *CertStatus")
	require.EqualValues(t, commands.CertNotAuthorized, status.ErrorCode,
		"a cert whose PublicKey is a different authority than the connected peer must be rejected")
}
