//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/katzenpost/katzenpost/fuzz/seed"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func FuzzUploadHandlersPayload(f *testing.F) {
	st, key, votingEpoch := newSingleAuthorityState(f)
	keyHash := hash.Sum256From(key.idPubKey)

	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("not-a-document"))
	f.Add(make([]byte, 8))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if seed.Export(payload) {
			return
		}
		signed, err := cert.Sign(key.idKey, key.idPubKey, payload, votingEpoch+100)
		if err != nil {
			return
		}

		if resp := st.onVoteUpload(&commands.Vote{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: signed}, keyHash[:]); resp == nil {
			t.Fatal("onVoteUpload returned nil")
		}
		if resp := st.onCertUpload(&commands.Cert{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: signed}, keyHash[:]); resp == nil {
			t.Fatal("onCertUpload returned nil")
		}
		if resp := st.onRevealUpload(&commands.Reveal{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: signed}, keyHash[:]); resp == nil {
			t.Fatal("onRevealUpload returned nil")
		}
		if resp := st.onSigUpload(&commands.Sig{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: signed}, keyHash[:]); resp == nil {
			t.Fatal("onSigUpload returned nil")
		}
	})
}
