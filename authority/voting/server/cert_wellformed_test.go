// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestOnCertUploadRejectsMalformedCertificate(t *testing.T) {
	ss := signSchemes.ByName("Ed25519")
	idPub, idPriv, err := ss.GenerateKey()
	require.NoError(t, err)
	pk := hash.Sum256From(idPub)
	strangerPub, strangerPriv, err := ss.GenerateKey()
	require.NoError(t, err)
	strangerHash := hash.Sum256From(strangerPub)

	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	votingEpoch, _, _ := epochtime.Now()

	st := &state{
		log:                   backend.GetLogger("cert-wellformed"),
		authorizedAuthorities: map[[publicKeyHashSize]byte]bool{pk: true},
		authorityNames:        map[[publicKeyHashSize]byte]string{pk: "peer"},
		reverseHash:           map[[publicKeyHashSize]byte]sign.PublicKey{pk: idPub},
		verifiers:             map[[publicKeyHashSize]byte]sign.PublicKey{pk: idPub},
		votingEpoch:           votingEpoch,
		votes: map[uint64]map[[publicKeyHashSize]byte]*pki.Document{
			votingEpoch: {pk: &pki.Document{Epoch: votingEpoch}},
		},
		certificates: map[uint64]map[[publicKeyHashSize]byte]*pki.Document{},
	}

	pair := func(priv sign.PrivateKey, pub sign.PublicKey, epoch uint64) ([]byte, []byte) {
		sr := new(pki.SharedRandom)
		c, err := sr.Commit(epoch)
		require.NoError(t, err)
		sc, err := cert.Sign(priv, pub, c, epoch+5)
		require.NoError(t, err)
		srv, err := cert.Sign(priv, pub, sr.Reveal(), epoch+5)
		require.NoError(t, err)
		return sc, srv
	}
	upload := func(doc *pki.Document) uint8 {
		signed, err := pki.SignDocument(idPriv, idPub, doc)
		require.NoError(t, err)
		resp := st.onCertUpload(&commands.Cert{Epoch: votingEpoch, PublicKey: idPub, Payload: signed}, pk[:])
		status, ok := resp.(*commands.CertStatus)
		require.True(t, ok)
		delete(st.certificates[votingEpoch], pk)
		return status.ErrorCode
	}
	otherPub, otherPriv, err := ss.GenerateKey()
	require.NoError(t, err)
	otherPk := hash.Sum256From(otherPub)
	st.reverseHash[otherPk], st.verifiers[otherPk] = otherPub, otherPub
	sc, sr := pair(idPriv, idPub, votingEpoch)
	oc, or := pair(otherPriv, otherPub, votingEpoch)
	base := func() *pki.Document {
		return &pki.Document{
			Version: pki.DocumentVersion, Epoch: votingEpoch, GenesisEpoch: votingEpoch,
			PKISignatureScheme: ss.Name(),
			SharedRandomCommit: map[[32]byte][]byte{pk: sc, otherPk: oc},
			SharedRandomReveal: map[[32]byte][]byte{pk: sr, otherPk: or},
		}
	}
	require.EqualValues(t, commands.CertNotSigned, upload(base()), "a certificate with no topology, gateway, or service node is malformed")

	scStranger, srStranger := pair(strangerPriv, strangerPub, votingEpoch)
	doc := base()
	doc.SharedRandomCommit[strangerHash] = scStranger
	doc.SharedRandomReveal[strangerHash] = srStranger
	require.EqualValues(t, commands.CertNotSigned, upload(doc), "a certificate citing a commit from an unknown authority is malformed")

	scStale, srStale := pair(idPriv, idPub, votingEpoch-1)
	doc = base()
	doc.SharedRandomCommit[pk] = scStale
	doc.SharedRandomReveal[pk] = srStale
	require.EqualValues(t, commands.CertNotSigned, upload(doc), "a certificate citing a stale commit is malformed")
}
