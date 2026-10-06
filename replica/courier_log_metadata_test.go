// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

func courierLogConn(t *testing.T, doc *pki.Document) (*incomingConn, func() string) {
	p := filepath.Join(t.TempDir(), "replica.log")
	logBackend, err := log.New(p, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logBackend.Close() })
	w := &PKIWorker{
		WorkerBase: pki.NewWorkerBase(nil, logBackend.GetLogger("pki")),
		replicas:   replicaCommon.NewReplicaMap(),
	}
	if doc != nil {
		w.SetDocumentForEpoch(doc.Epoch, doc, nil)
	}
	c := &incomingConn{
		l:   &Listener{server: &Server{PKIWorker: w}},
		log: logBackend.GetLogger("incoming"),
	}
	return c, func() string {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		return string(b)
	}
}

func requireNoPeerLinkKey(t *testing.T, out string, creds *wire.PeerCredentials) {
	key := strings.TrimSpace(pem.ToPublicPEMString(creds.PublicKey))
	lines := strings.Split(key, "\n")
	require.Greater(t, len(lines), 2)
	for _, line := range lines[1 : len(lines)-1] {
		require.NotContains(t, out, line)
	}
}

func TestReplicaDoesNotLogCourierLinkKey(t *testing.T) {
	linkPub, _, err := kemschemes.ByName("xwing").GenerateKeyPair()
	require.NoError(t, err)
	epoch, _, _ := epochtime.Now()

	for _, tc := range []struct {
		name string
		doc  *pki.Document
		ad   []byte
	}{
		{"no document", nil, nil},
		{"unknown courier", &pki.Document{Epoch: epoch}, nil},
		{"bad additional data", &pki.Document{Epoch: epoch}, []byte{1, 2, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, out := courierLogConn(t, tc.doc)
			creds := &wire.PeerCredentials{AdditionalData: tc.ad, PublicKey: linkPub}
			require.False(t, c.IsPeerValid(creds))
			requireNoPeerLinkKey(t, out(), creds)
		})
	}
}
