// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
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

func TestReplyFromANonEchoServiceIsPrintableASCII(t *testing.T) {
	cases := map[string][2]string{
		"ANSI color":         {"\x1b[31mred", "[31mred"},
		"OSC 52 clipboard":   {"\x1b]52;c;aGk=\x07", "]52;c;aGk="},
		"tab":                {"a\tb", "ab"},
		"carriage return":    {"a\rb", "ab"},
		"NUL":                {"a\x00b", "ab"},
		"DEL":                {"a\x7fb", "ab"},
		"zero-width space":   {"zero\xe2\x80\x8bwidth", "zerowidth"},
		"bidi override":      {"bidi\xe2\x80\xaeoverride", "bidioverride"},
		"non-breaking space": {"nb\xc2\xa0sp", "nbsp"},
		"over-long":          {strings.Repeat("m", 1500), strings.Repeat("m", 1024)},
		"clean multi-line":   {"line one\nline two\n", "line one\nline two\n"},
	}
	for name, c := range cases {
		ok, got := replyDelivered("motd", []byte(c[0]), []byte("ping"))
		require.True(t, ok, name)
		require.Equal(t, c[1], string(got), name)
	}
}

func TestABatchPrintsOneNonEchoReply(t *testing.T) {
	lb, err := log.New(filepath.Join(t.TempDir(), "ping.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	first := new(firstReply)
	var out bytes.Buffer
	first.print(&out, io.Discard, lb.GetLogger("ping"), "motd")
	require.Empty(t, out.String(), "a batch with no reply printed one")
	for _, r := range []string{"hello\x00\x00", "again", "and again"} {
		first.keep(nil)
		first.keep([]byte(r))
	}
	first.print(&out, io.Discard, lb.GetLogger("ping"), "motd")
	require.Equal(t, "motd replied: \"hello\"\n", out.String())
}
