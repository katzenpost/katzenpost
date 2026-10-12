// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

const goldenNoticeFreeDocument = "b3624d75f934006545706f636807674c616d62646147f90000674c616d6264614cf90000674c616d6264614df90000674c616d62646150f90000674c616d62646152f900006756657273696f6e62763168546f706f6c6f6779f66c476174657761794e6f646573f66c47656e6573697345706f6368036c536572766963654e6f646573f66f53746f726167655265706c69636173f6715072696f7253686172656452616e646f6df67153686172656452616e646f6d56616c75654301020372504b495369676e6174757265536368656d65704564323535313920537068696e63732b7253686172656452616e646f6d436f6d6d6974f67253686172656452616e646f6d52657665616cf672537068696e7847656f6d6574727948617368f6"

func noticeTestDocument() *Document {
	return &Document{Version: DocumentVersion, Epoch: 7, GenesisEpoch: 3, Mu: 0.25, SharedRandomValue: []byte{1, 2, 3}, PKISignatureScheme: "Ed25519 Sphincs+"}
}

func TestDocumentWithoutNoticeEncodesAsBefore(t *testing.T) {
	b, err := ccbor.Marshal((*document)(noticeTestDocument()))
	require.NoError(t, err)
	require.Equal(t, goldenNoticeFreeDocument, hex.EncodeToString(b))
}

func TestDocumentNoticeRoundTrips(t *testing.T) {
	d := noticeTestDocument()
	d.MinClientVersion = "v0.0.105"
	d.ClientNotice = "upgrade before 2026-11-01"
	b, err := ccbor.Marshal((*document)(d))
	require.NoError(t, err)
	got := new(document)
	require.NoError(t, cbor.Unmarshal(b, got))
	require.Equal(t, "v0.0.105", got.MinClientVersion)
	require.Equal(t, "upgrade before 2026-11-01", got.ClientNotice)
}

func TestIsClientNoticeWellFormed(t *testing.T) {
	require.NoError(t, IsClientNoticeWellFormed("", ""))
	require.NoError(t, IsClientNoticeWellFormed(strings.Repeat("v", 32), strings.Repeat("n", 512)))
	require.Error(t, IsClientNoticeWellFormed(strings.Repeat("v", 33), ""))
	require.Error(t, IsClientNoticeWellFormed("", strings.Repeat("n", 513)))
	require.Error(t, IsClientNoticeWellFormed("v1\n", ""))
	require.Error(t, IsClientNoticeWellFormed("", "caf\xc3\xa9"))
}

func TestIsDocumentWellFormedIgnoresNotice(t *testing.T) {
	d := &Document{Version: DocumentVersion, Epoch: 1, GenesisEpoch: 1}
	d.ClientNotice = strings.Repeat("n", 513) + "\n"
	d.MinClientVersion = strings.Repeat("v", 33)
	err := IsDocumentWellFormed(d, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "ClientNotice")
	require.NotContains(t, err.Error(), "MinClientVersion")
}
