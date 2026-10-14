// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

type UDPBuffers struct {
	Receive    int
	Send       int
	ReceiveMax int
	SendMax    int
}

func desiredUDPBuffer() int {
	if runtime.GOOS == "openbsd" {
		return 2 << 20
	}
	return 7 << 20
}

func udpBufferSysctls() (receive, send string) {
	if runtime.GOOS == "linux" {
		return "net.core.rmem_max", "net.core.wmem_max"
	}
	return "kern.ipc.maxsockbuf", "kern.ipc.maxsockbuf"
}

func readSysctlInt(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return n
}

func readUDPBuffers(c syscall.Conn) UDPBuffers {
	receive, send := socketBuffers(c)
	return UDPBuffers{
		Receive:    receive,
		Send:       send,
		ReceiveMax: readSysctlInt("/proc/sys/net/core/rmem_max"),
		SendMax:    readSysctlInt("/proc/sys/net/core/wmem_max"),
	}
}

func lowBuffer(name string, got int, sysctl string, max, want int) string {
	now := ""
	if max > 0 {
		now = fmt.Sprintf(", now %d", max)
	}
	return fmt.Sprintf("%s buffer is %d KiB: raise %s%s, e.g. sysctl -w %s=%d", name, got>>10, sysctl, now, sysctl, want)
}

func (b UDPBuffers) Warning() string {
	want := desiredUDPBuffer()
	receiveSysctl, sendSysctl := udpBufferSysctls()
	var low []string
	if b.Receive > 0 && b.Receive < want {
		low = append(low, lowBuffer("receive", b.Receive, receiveSysctl, b.ReceiveMax, want))
	}
	if b.Send > 0 && b.Send < want {
		low = append(low, lowBuffer("send", b.Send, sendSysctl, b.SendMax, want))
	}
	if len(low) == 0 {
		return ""
	}
	return fmt.Sprintf("QUIC UDP socket buffers are below the %d KiB quic-go wants: %s", want>>10, strings.Join(low, "; "))
}

func (l *QuicListener) UDPBuffers() UDPBuffers {
	return l.udpBuffers
}

func UDPBufferErrors() (receive, send uint64, ok bool) {
	snmp, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return 0, 0, false
	}
	return parseUDPBufferErrors(snmp)
}

func parseUDPBufferErrors(snmp []byte) (receive, send uint64, ok bool) {
	var header []string
	lines := bufio.NewScanner(bytes.NewReader(snmp))
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) == 0 || fields[0] != "Udp:" {
			continue
		}
		if header == nil {
			header = fields
			continue
		}
		if len(fields) != len(header) {
			return 0, 0, false
		}
		value := func(name string) (uint64, bool) {
			i := slices.Index(header, name)
			if i < 0 {
				return 0, false
			}
			v, err := strconv.ParseUint(fields[i], 10, 64)
			return v, err == nil
		}
		receive, receiveOK := value("RcvbufErrors")
		send, sendOK := value("SndbufErrors")
		return receive, send, receiveOK && sendOK
	}
	return 0, 0, false
}
