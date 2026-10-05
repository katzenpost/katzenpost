// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
)

func TestPKIWorkerDoesNotCacheBadReply(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)
	cfg.Callbacks = &config.Callbacks{}

	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  &mockPKIClient{deserializeErr: errors.New("bad signature")},
	}

	p := newPKI(c)
	c.pki = p
	p.consensusGetter = new(mockConsensusGetter)

	p.Go(p.worker)
	epoch, _, _ := epochtime.Now()
	p.forceUpdateCh <- true
	time.Sleep(100 * time.Millisecond)
	p.forceUpdateCh <- true
	time.Sleep(100 * time.Millisecond)
	p.Halt()

	require.NotContains(t, p.failedFetches, epoch)
	require.NotContains(t, p.failedFetches, epoch+1)
	require.NotContains(t, p.failedFetches, epoch-1)
}
