// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"

	kpcommon "github.com/katzenpost/katzenpost/common"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/loops"
)

type capturePoster struct {
	rejectOncePoster
	mu    sync.Mutex
	descs []*cpki.MixDescriptor
}

func (f *capturePoster) Post(_ context.Context, _ uint64, _ sign.PrivateKey, _ sign.PublicKey, d *cpki.MixDescriptor, _ *loops.LoopStats) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.descs = append(f.descs, d)
	return nil
}

func TestPublishedDescriptorCarriesConfiguredMetadata(t *testing.T) {
	for _, tc := range []struct{ contact, version, want string }{
		{"", "", ""},
		{"ops@example.org", "custom 1.0", "custom 1.0"},
		{"ops@example.org", cpki.AutoSoftwareVersion, cpki.ResolveSoftwareVersion(cpki.AutoSoftwareVersion, kpcommon.Version())},
	} {
		setEpochClock(t, 1000, time.Second)
		f := &capturePoster{}
		p := newPublishPKI(t, f)
		p.glue.Config().Server.ContactInfo = tc.contact
		p.glue.Config().Server.SoftwareVersion = tc.version
		require.NoError(t, p.publishDescriptorIfNeeded(context.Background()))
		require.Len(t, f.descs, 1)
		require.Equal(t, tc.contact, f.descs[0].ContactInfo)
		require.Equal(t, tc.want, f.descs[0].SoftwareVersion)
		require.NotEqual(t, cpki.AutoSoftwareVersion, f.descs[0].SoftwareVersion)
	}
}
