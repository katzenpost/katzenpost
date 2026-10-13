// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestPeerDialLogsItsTransport(t *testing.T) {
	_, identityPrivateKey, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	keys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys)
	require.NoError(t, err)
	defer l.Close()
	st := &state{}
	out := fileLogged(t, st)
	peer := &config.Authority{Identifier: "auth2"}
	conn, err := st.dialPeerAddrs(peer, []string{"quic://" + l.Addr().String()}, 5*time.Second)
	require.NoError(t, err)
	conn.Close()
	require.Contains(t, out(), "peer auth2: quic connection established.")
}
