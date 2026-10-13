// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/pki"
)

func TestReplicaPublishedDescriptorCarriesConfiguredMetadata(t *testing.T) {
	for _, tc := range []struct{ contact, version, want string }{
		{"", "", ""},
		{"ops@example.org", "custom 1.0", "custom 1.0"},
		{"ops@example.org", pki.AutoSoftwareVersion, pki.ResolveSoftwareVersion(pki.AutoSoftwareVersion, kpcommon.Version())},
	} {
		setReplicaEpochClock(t, 1000, time.Second)
		f := &mockReplicaPKIClient{}
		w, cleanup := createPublishDescriptorTestWorker(t, f)
		w.server.cfg.ContactInfo = tc.contact
		w.server.cfg.SoftwareVersion = tc.version
		require.NoError(t, w.publishDescriptorIfNeeded(context.Background()))
		cleanup()
		_, descs := f.posts()
		require.Len(t, descs, 1)
		require.Equal(t, tc.contact, descs[0].ContactInfo)
		require.Equal(t, tc.want, descs[0].SoftwareVersion)
		require.NotEqual(t, pki.AutoSoftwareVersion, descs[0].SoftwareVersion)
	}
}
