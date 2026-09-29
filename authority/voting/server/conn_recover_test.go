// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

// TestHandleConnRecoversFromPanic verifies that a panic inside onConn is
// contained by handleConn instead of crashing the authority. A bogus wire KEM
// scheme makes onConn panic deterministically early.
func TestHandleConnRecoversFromPanic(t *testing.T) {
	require := require.New(t)

	params := &config.Parameters{Mu: 0.001, LambdaP: 0.002, LambdaL: 0.0005, LambdaM: 0.2}
	keys, authCfgs, err := genVotingAuthoritiesCfg(params, 1)
	require.NoError(err)

	cfg := authCfgs[0]
	cfg.Server.WireKEMScheme = "not-a-real-kem-scheme" // makes onConn panic

	s := &Server{
		cfg:               cfg,
		identityPublicKey: keys[0].idPubKey,
		fatalErrCh:        make(chan error, 1),
		haltedCh:          make(chan interface{}),
	}
	lb, err := log.New("", "DEBUG", false)
	require.NoError(err)
	s.logBackend = lb
	s.log = lb.GetLogger("conn-recover-test")
	st := new(state)
	st.s = s
	s.state = st

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	require.NotPanics(func() { s.handleConn(server) })
}
