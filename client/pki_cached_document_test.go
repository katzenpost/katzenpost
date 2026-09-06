// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func newCachedDocumentPKI(t *testing.T, doc *cpki.Document) *pki {
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	return newPKI(&Client{logbackend: logbackend, cfg: &config.Config{Debug: &config.Debug{}, CachedDocument: doc}})
}

func TestCachedDocumentServesAsCurrent(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	doc := &cpki.Document{Epoch: epoch, Signatures: map[[32]byte]cert.Signature{{1}: {}}}
	p := newCachedDocumentPKI(t, doc)

	require.Equal(t, epoch, p.GetDocumentByEpoch(epoch).Epoch)
	blob, cur := p.currentDocument()
	require.NotNil(t, cur)
	require.Equal(t, epoch, cur.Epoch)
	require.NotEmpty(t, blob)
	require.Nil(t, p.rawSignedDocumentByEpoch(epoch))
	require.NotEmpty(t, doc.Signatures)
}

func TestCachedDocumentForAnotherEpochIsNotCurrent(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	p := newCachedDocumentPKI(t, &cpki.Document{Epoch: epoch + 5})

	blob, cur := p.currentDocument()
	require.Nil(t, cur)
	require.Nil(t, blob)
	require.Equal(t, epoch+5, p.GetDocumentByEpoch(epoch+5).Epoch)
}
