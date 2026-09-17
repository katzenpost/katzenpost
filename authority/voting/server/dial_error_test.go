// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

// TestDialAndHandshakePeerPreservesDialErrorWhenLastAddressUnparseable proves
// the informative dial-failure error survives when the LAST address fails to
// parse rather than to dial. The address loop only surfaced the accumulated
// error on a final dial failure; if the final address failed url.Parse instead,
// it fell through to a generic "no usable address" message and discarded the
// real reason an earlier address could not be reached.
func TestDialAndHandshakePeerPreservesDialErrorWhenLastAddressUnparseable(t *testing.T) {
	require := require.New(t)

	st, _, _ := mkAuthState(t, "sender", "Xwing")

	sentinel := errors.New("sentinel-dial-error")
	st.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, sentinel
	}

	peer := &config.Authority{Identifier: "peer"}
	// A dialable-but-failing address first, an unparseable address last.
	addrs := []string{"tcp://127.0.0.1:1", "://bad"}

	_, _, err := st.dialAndHandshakePeer(peer, addrs)
	require.Error(err)
	require.True(strings.Contains(err.Error(), sentinel.Error()),
		"the dial-failure error must be preserved, got: %v", err)
}
