// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestReplyDeliveredFromANonEchoService(t *testing.T) {
	var ok bool
	var got []byte
	require.NotPanics(t, func() { ok, got = replyDelivered("motd", []byte("hello\x00\x00"), []byte("ping")) })
	require.True(t, ok)
	require.Equal(t, []byte("hello"), got)
}

func TestReplyDeliveredFromEcho(t *testing.T) {
	sent := []byte("ping")
	echoed, err := cbor.Marshal(sent)
	require.NoError(t, err)
	ok, _ := replyDelivered("echo", echoed, sent)
	require.True(t, ok)
	other, err := cbor.Marshal([]byte("pong"))
	require.NoError(t, err)
	ok, _ = replyDelivered("echo", other, sent)
	require.False(t, ok)
	require.NotPanics(t, func() { ok, _ = replyDelivered("echo", []byte("hello"), sent) })
	require.False(t, ok)
}
