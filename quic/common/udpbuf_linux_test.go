// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"os"
	"strconv"
	"strings"
	"testing"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"
)

func sysctlInt(t *testing.T, path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	require.NoError(t, err)
	return n
}

func TestListenerReportsUDPBuffers(t *testing.T) {
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, newTestEpochKeys(t, t.TempDir(), newEpochClock(CurrentEpoch())), nil)
	require.NoError(t, err)
	defer l.Close()
	b := l.UDPBuffers()
	require.Positive(t, b.Receive)
	require.Positive(t, b.Send)
	require.Equal(t, sysctlInt(t, "/proc/sys/net/core/rmem_max"), b.ReceiveMax)
	require.Equal(t, sysctlInt(t, "/proc/sys/net/core/wmem_max"), b.SendMax)
}

func TestUDPBufferWarning(t *testing.T) {
	require.Empty(t, UDPBuffers{Receive: 8 << 20, Send: 8 << 20}.Warning())
	w := UDPBuffers{Receive: 416 << 10, Send: 8 << 20, ReceiveMax: 212992, SendMax: 212992}.Warning()
	require.Contains(t, w, "net.core.rmem_max")
	require.Contains(t, w, "212992")
	require.NotContains(t, w, "net.core.wmem_max")
	w = UDPBuffers{Receive: 8 << 20, Send: 416 << 10}.Warning()
	require.Contains(t, w, "net.core.wmem_max")
	require.NotContains(t, w, "net.core.rmem_max")
}

func TestUDPBufferErrors(t *testing.T) {
	snmp := "Ip: Forwarding DefaultTTL\nIp: 1 64\n" +
		"Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n" +
		"Udp: 10 2 3 40 5 6 0 0 0\n" +
		"UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n" +
		"UdpLite: 0 0 0 0 7 8 0 0 0\n"
	receive, send, ok := parseUDPBufferErrors([]byte(snmp))
	require.True(t, ok)
	require.Equal(t, uint64(5), receive)
	require.Equal(t, uint64(6), send)
	for _, bad := range []string{"", "Udp: RcvbufErrors\n", "Udp: RcvbufErrors SndbufErrors\nUdp: x 1\n", "Udp: InDatagrams\nUdp: 1\n"} {
		_, _, ok = parseUDPBufferErrors([]byte(bad))
		require.False(t, ok, "%q", bad)
	}
	if _, err := os.Stat("/proc/net/snmp"); err == nil {
		_, _, ok = UDPBufferErrors()
		require.True(t, ok)
	}
}
