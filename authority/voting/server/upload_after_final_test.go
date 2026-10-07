// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func parkedInPersist(handler string) bool {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, handler) && strings.Contains(g, "bbolt") {
			return true
		}
	}
	return false
}

func TestUploadRejectedOnceDocumentIsFinal(t *testing.T) {
	for _, kind := range []string{"mix", "replica"} {
		t.Run(kind, func(t *testing.T) {
			f := newUploadFixture(t, testSchemeName)
			post, handler := f.postMix, "(*state).onDescriptorUpload("
			if kind == "replica" {
				post, handler = f.postReplica, "(*state).onReplicaDescriptorUpload("
			}
			st := f.srv.state
			tx, err := st.db.Begin(true)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			done := make(chan uint8, 1)
			go func() {
				defer close(done)
				done <- post(t, "1")
			}()
			require.Eventually(t, func() bool { return parkedInPersist(handler) }, 10*time.Second, time.Millisecond)
			st.Lock()
			st.documents[f.epoch] = &pki.Document{}
			st.Unlock()
			require.NoError(t, tx.Rollback())
			require.Equal(t, uint8(commands.DescriptorConflict), <-done)
			st.RLock()
			defer st.RUnlock()
			require.Empty(t, st.descriptors[f.epoch])
			require.Empty(t, st.replicaDescriptors[f.epoch])
		})
	}
}
