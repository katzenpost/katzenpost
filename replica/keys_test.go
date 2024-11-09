// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/log"
)

func TestEnvelopeKeys(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	dname, err := os.MkdirTemp("", "replca.testState")
	require.NoError(t, err)
	defer os.RemoveAll(dname)

	replicaScheme := nikeschemes.ByName("x25519")
	keys := &EnvelopeKeys{
		log:      logBackend.GetLogger("envelope keys"),
		datadir:  dname,
		scheme:   replicaScheme,
		keysLock: new(sync.RWMutex),
		keys:     make(map[uint64]*EnvelopeKey),
	}
	epoch, _, _ := ReplicaNow()
	err = keys.Generate(epoch)
	require.NoError(t, err)

	ok := keys.Prune()
	require.False(t, ok)

	err = keys.Generate(epoch - 20)
	require.NoError(t, err)

	ok = keys.Prune()
	require.True(t, ok)

	keys.keysLock.Lock()
	l := len(keys.keys)
	keys.keysLock.Unlock()
	require.Equal(t, 1, l)

	keypair, err := keys.GetKeypair(epoch)
	require.NoError(t, err)
	require.NotNil(t, keypair)

	keypair, err = keys.EnsureKey(epoch - 20)
	require.Error(t, err)
	require.Nil(t, keypair)

	keypair, err = keys.EnsureKey(epoch - 10)
	require.NoError(t, err)
	require.NotNil(t, keypair)

	keypair.PurgeKeyFiles(dname, replicaScheme, epoch)
}
