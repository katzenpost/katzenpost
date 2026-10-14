// SPDX-License-Identifier: AGPL-3.0-only

package mixclient

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/log"
)

func replyLogger(t *testing.T, level string) (*logging.Logger, string) {
	f := filepath.Join(t.TempDir(), "reply.log")
	lb, err := log.New(f, level, false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	return lb.GetLogger("reply"), f
}

func TestPrintableReplyDropsThePadding(t *testing.T) {
	l, _ := replyLogger(t, "ERROR")
	reply := append([]byte("hello from the testnet"), make([]byte, 64)...)
	require.Equal(t, "hello from the testnet", string(PrintableReply(reply, io.Discard, l)))
}

func TestPrintableReplyKeepsOnlyPrintableASCIIAndLineFeeds(t *testing.T) {
	l, _ := replyLogger(t, "ERROR")
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
		"invalid UTF-8 CSI":  {"a\x9b31mb", "a31mb"},
		"over-long":          {strings.Repeat("m", 1500), strings.Repeat("m", 1024)},
		"clean multi-line":   {"maintenance tonight\n  see https://example.org/ ~\n", "maintenance tonight\n  see https://example.org/ ~\n"},
	}
	for name, c := range cases {
		reply := append([]byte(c[0]), make([]byte, 64)...)
		require.Equal(t, c[1], string(PrintableReply(reply, io.Discard, l)), name)
	}
}

func TestPrintableReplyNoticesWhatItChanged(t *testing.T) {
	l, _ := replyLogger(t, "ERROR")
	cases := map[string]struct{ reply, notice string }{
		"clean":     {"hello\nworld\n", ""},
		"ANSI":      {"\x1b[31mred", "removed 1 disallowed byte(s) from the reply\n"},
		"bidi":      {"bidi\xe2\x80\xaeoverride", "removed 3 disallowed byte(s) from the reply\n"},
		"interior":  {"a\x00b", "removed 1 disallowed byte(s) from the reply\n"},
		"over-long": {strings.Repeat("m", 1500), "cut the reply at 1024 bytes\n"},
		"both":      {"\x1b]52;c;aGk=\x07" + strings.Repeat("m", 1500), "removed 2 disallowed byte(s) from the reply\ncut the reply at 1024 bytes\n"},
	}
	for name, c := range cases {
		var notices bytes.Buffer
		PrintableReply(append([]byte(c.reply), make([]byte, 64)...), &notices, l)
		require.Equal(t, c.notice, notices.String(), name)
	}
}

func TestPrintableReplyLogsTheRawReplyInHexAtDebugOnly(t *testing.T) {
	reply := append([]byte("\x1b[31mred"), make([]byte, 8)...)
	for level, logged := range map[string]bool{"DEBUG": true, "INFO": false, "NOTICE": false, "ERROR": false} {
		l, f := replyLogger(t, level)
		PrintableReply(reply, io.Discard, l)
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		require.Equal(t, logged, strings.Contains(string(b), hex.EncodeToString(reply)), level)
	}
}
