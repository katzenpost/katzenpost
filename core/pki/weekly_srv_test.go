// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

const weeklySRVGolden = "b3624d75f900006545706f636807674c616d62646147f90000674c616d6264614cf90000674c616d6264614df90000674c616d62646150f90000674c616d62646152f900006756657273696f6e62763168546f706f6c6f6779f66c476174657761794e6f646573f66c47656e6573697345706f6368036c536572766963654e6f646573f66f53746f726167655265706c69636173f6715072696f7253686172656452616e646f6d824204054206077153686172656452616e646f6d56616c75654301020372504b495369676e6174757265536368656d65607253686172656452616e646f6d436f6d6d6974f67253686172656452616e646f6d52657665616cf672537068696e7847656f6d6574727948617368f6"

func weeklySRVDoc() *Document {
	return &Document{Epoch: 7, GenesisEpoch: 3, SharedRandomValue: []byte{1, 2, 3}, WeeklySharedRandom: [][]byte{{4, 5}, {6, 7}}, Version: DocumentVersion}
}

func TestWeeklySharedRandomKeepsWireKey(t *testing.T) {
	b, err := ccbor.Marshal((*document)(weeklySRVDoc()))
	require.NoError(t, err)
	require.Equal(t, weeklySRVGolden, hex.EncodeToString(b))

	var m map[string]interface{}
	require.NoError(t, cbor.Unmarshal(b, &m))
	require.Contains(t, m, "PriorSharedRandom")
	require.NotContains(t, m, "WeeklySharedRandom")
}

func TestWeeklySharedRandomDecodesOldDocuments(t *testing.T) {
	b, err := hex.DecodeString(weeklySRVGolden)
	require.NoError(t, err)
	d := new(Document)
	require.NoError(t, cbor.Unmarshal(b, (*document)(d)))
	require.Equal(t, [][]byte{{4, 5}, {6, 7}}, d.WeeklySharedRandom)
}

func TestWeeklySharedRandomRequiredAfterGenesis(t *testing.T) {
	d := weeklySRVDoc()
	d.WeeklySharedRandom = nil
	require.ErrorContains(t, IsDocumentWellFormed(d, nil), "WeeklySharedRandom")
}
