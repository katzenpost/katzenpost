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

// onCertUpload gates on the command epoch (certificate.Epoch, chosen by the
// sender) but never checks the epoch inside the parsed certificate document.
// onVoteUpload already binds its document epoch to the voting epoch; this test
// pins that onCertUpload must do the same, so a byzantine authority cannot
// replay a victim's genuine prior-epoch certificate into the current epoch's
// first-write-wins slot. It signs a document for the prior epoch, wraps it in a
// cert whose command epoch is the current voting epoch, and expects a rejection.
func TestOnCertUploadBindsDocumentEpoch(t *testing.T) {
	ss := signSchemes.ByName("Ed25519")
	require.NotNil(t, ss)
	idPub, idPriv, err := ss.GenerateKey()
	require.NoError(t, err)
	pk := hash.Sum256From(idPub)

	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	now, _, _ := epochtime.Now()
	votingEpoch := now

	st := &state{
		log:                   backend.GetLogger("cert-epoch"),
		authorizedAuthorities: map[[publicKeyHashSize]byte]bool{pk: true},
		authorityNames:        map[[publicKeyHashSize]byte]string{pk: "attacker"},
		votingEpoch:           votingEpoch,
		votes: map[uint64]map[[publicKeyHashSize]byte]*pki.Document{
			// The peer's vote for this epoch is already recorded, so the cert
			// passes the "vote seen first" gate.
			votingEpoch: {pk: &pki.Document{Epoch: votingEpoch}},
		},
		certificates: map[uint64]map[[publicKeyHashSize]byte]*pki.Document{},
	}

	// A genuine certificate document for a PRIOR epoch. Its expiration is
	// doc.Epoch+5 (pki.Document.MarshalCertificate), so it is still verifiable
	// within the current epoch and cert.Verify succeeds.
	doc := &pki.Document{
		Epoch:              votingEpoch - 1,
		GenesisEpoch:       votingEpoch - 1,
		PKISignatureScheme: ss.Name(),
	}
	signed, err := pki.SignDocument(idPriv, idPub, doc)
	require.NoError(t, err)

	// Command epoch is attacker-chosen; set it to votingEpoch so the replay
	// passes the too-early/too-late gates. Only the inner document epoch differs.
	resp := st.onCertUpload(&commands.Cert{
		Epoch:     votingEpoch,
		PublicKey: idPub,
		Payload:   signed,
	}, pk[:])
	status, ok := resp.(*commands.CertStatus)
	require.True(t, ok, "onCertUpload must return a *CertStatus")

	if status.ErrorCode == commands.CertOk {
		t.Fatalf("onCertUpload accepted a cert whose document epoch (%d) != voting epoch (%d): "+
			"a genuine prior-epoch cert can be replayed into this epoch's first-write-wins slot",
			doc.Epoch, votingEpoch)
	}
	require.EqualValues(t, commands.CertNotSigned, status.ErrorCode,
		"a cert whose document epoch is not the voting epoch must be rejected with CertNotSigned")
}
