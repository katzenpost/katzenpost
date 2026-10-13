// SPDX-License-Identifier: AGPL-3.0-only

package common

type UDPBuffers struct {
	Receive    int
	Send       int
	ReceiveMax int
	SendMax    int
}

func (b UDPBuffers) Warning() string {
	return ""
}

func (l *QuicListener) UDPBuffers() UDPBuffers {
	return l.udpBuffers
}

func UDPBufferErrors() (receive, send uint64, ok bool) {
	return 0, 0, false
}

func parseUDPBufferErrors(snmp []byte) (receive, send uint64, ok bool) {
	return 0, 0, false
}
