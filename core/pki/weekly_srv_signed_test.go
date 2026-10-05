// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
)

func TestWeeklySharedRandomSurvivesHybridSigning(t *testing.T) {
	scheme := signSchemes.ByName("Ed25519 Sphincs+")
	pub, priv, err := scheme.GenerateKey()
	require.NoError(t, err)
	now, _, _ := epochtime.Now()
	d := weeklySRVDoc()
	d.Epoch = now
	d.GenesisEpoch = now - 1
	d.PKISignatureScheme = scheme.Name()

	signed, err := SignDocument(priv, pub, d)
	require.NoError(t, err)
	got, err := FromPayload(pub, signed)
	require.NoError(t, err)
	require.Equal(t, [][]byte{{4, 5}, {6, 7}}, got.WeeklySharedRandom)

	payload, err := cert.GetCertified(signed)
	require.NoError(t, err)
	var m map[string]interface{}
	require.NoError(t, cbor.Unmarshal(payload, &m))
	require.Equal(t, []interface{}{[]byte{4, 5}, []byte{6, 7}}, m["PriorSharedRandom"])
	require.NotContains(t, m, "WeeklySharedRandom")
}

func TestWeeklySharedRandomOptionalAtGenesis(t *testing.T) {
	with := weeklySRVDoc()
	with.GenesisEpoch = with.Epoch
	without := weeklySRVDoc()
	without.GenesisEpoch = without.Epoch
	without.WeeklySharedRandom = nil
	require.Equal(t, IsDocumentWellFormed(with, nil), IsDocumentWellFormed(without, nil))
}

func TestDocumentStringNamesWeeklySharedRandom(t *testing.T) {
	require.Contains(t, weeklySRVDoc().String(), "WeeklySharedRandom: ")
}
