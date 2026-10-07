// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func TestShutdownWipesHeldSURBKeys(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)
	port, err := getFreePort()
	require.NoError(t, err)
	cfg.Listen.Tcp.Address = fmt.Sprintf("localhost:%d", port)

	d, err := NewDaemon(cfg)
	require.NoError(t, err)
	require.NoError(t, d.Start())

	replyKey := bytes.Repeat([]byte{0xf1}, 32)
	decoyKey := bytes.Repeat([]byte{0xf2}, 32)
	arqKey := bytes.Repeat([]byte{0xf3}, 32)
	arqSurbID := &[sphinxConstants.SURBIDLength]byte{3}
	d.replyLock.Lock()
	d.replies[[sphinxConstants.SURBIDLength]byte{1}] = replyDescriptor{appID: &[AppIDLength]byte{}, surbKey: replyKey}
	d.decoys[[sphinxConstants.SURBIDLength]byte{2}] = replyDescriptor{appID: &[AppIDLength]byte{}, surbKey: decoyKey}
	d.arqSurbIDMap[*arqSurbID] = &ARQMessage{AppID: &[AppIDLength]byte{}, SURBID: arqSurbID, SURBDecryptionKeys: arqKey}
	d.replyLock.Unlock()

	d.Shutdown()

	d.replyLock.Lock()
	defer d.replyLock.Unlock()
	requireSURBKeyWiped(t, replyKey, "reply SURB key left in memory after Shutdown")
	requireSURBKeyWiped(t, decoyKey, "decoy SURB key left in memory after Shutdown")
	requireSURBKeyWiped(t, arqKey, "ARQ SURB key left in memory after Shutdown")
}
