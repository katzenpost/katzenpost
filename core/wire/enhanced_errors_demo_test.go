// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"testing"
)

func TestEnhancedErrorMessages(t *testing.T) {
	// Test HandshakeError creation and formatting
	hsErr := &HandshakeError{
		State:       HandshakeStateMsg2Receive,
		Message:     "failed to process message 2",
		IsInitiator: true,
		Connection: &ConnectionInfo{
			Protocol:   "tcp",
			LocalAddr:  "127.0.0.1:8080",
			RemoteAddr: "192.168.1.100:9000",
			LocalIP:    "127.0.0.1",
			LocalPort:  "8080",
			RemoteIP:   "192.168.1.100",
			RemotePort: "9000",
		},
		ProtocolName: "PqXX",
		KEMScheme:    "XWING",
		MessageNumber: 2,
		MessageSize:   2500,
		ExpectedSize:  2628,
	}

	// Test basic error message
	basicErr := hsErr.Error()
	t.Logf("Basic error message:\n%s", basicErr)

	// Test verbose error message
	verboseErr := hsErr.Verbose()
	t.Logf("Verbose error message:\n%s", verboseErr)

	// Test error type checking
	if !IsHandshakeError(hsErr) {
		t.Error("IsHandshakeError should return true for HandshakeError")
	}

	// Test verbose error extraction
	verboseFromInterface := GetVerboseError(hsErr)
	if verboseFromInterface != verboseErr {
		t.Error("GetVerboseError should return the same as Verbose() method")
	}

	// Test structured error access
	if extractedErr, ok := GetHandshakeError(hsErr); ok {
		if extractedErr.State != HandshakeStateMsg2Receive {
			t.Errorf("Expected state %s, got %s", HandshakeStateMsg2Receive, extractedErr.State)
		}
		if extractedErr.MessageNumber != 2 {
			t.Errorf("Expected message number 2, got %d", extractedErr.MessageNumber)
		}
	} else {
		t.Error("GetHandshakeError should successfully extract HandshakeError")
	}
}

func TestProtocolVersionError(t *testing.T) {
	pvErr := &ProtocolVersionError{
		Expected: []byte{0x03},
		Received: []byte{0x02},
		Connection: &ConnectionInfo{
			Protocol:   "tcp",
			LocalAddr:  "127.0.0.1:8080",
			RemoteAddr: "192.168.1.100:9000",
			LocalIP:    "127.0.0.1",
			LocalPort:  "8080",
			RemoteIP:   "192.168.1.100",
			RemotePort: "9000",
		},
	}

	// Test basic error message
	basicErr := pvErr.Error()
	t.Logf("Protocol version error:\n%s", basicErr)

	// Test verbose error message
	verboseErr := pvErr.Verbose()
	t.Logf("Verbose protocol version error:\n%s", verboseErr)

	// Test error type checking
	if !IsProtocolVersionError(pvErr) {
		t.Error("IsProtocolVersionError should return true for ProtocolVersionError")
	}
}

func TestConnectionInfoFormatting(t *testing.T) {
	// Test TCP connection info
	tcpInfo := &ConnectionInfo{
		Protocol:   "tcp",
		LocalAddr:  "127.0.0.1:8080",
		RemoteAddr: "192.168.1.100:9000",
		LocalIP:    "127.0.0.1",
		LocalPort:  "8080",
		RemoteIP:   "192.168.1.100",
		RemotePort: "9000",
	}

	hsErr := &HandshakeError{
		State:      HandshakeStateAuthentication,
		Message:    "peer authentication failed",
		Connection: tcpInfo,
	}

	verbose := hsErr.Verbose()
	t.Logf("TCP connection error:\n%s", verbose)

	// Test QUIC connection info
	quicInfo := &ConnectionInfo{
		Protocol:   "quic",
		LocalAddr:  "[::1]:8080",
		RemoteAddr: "[2001:db8::1]:9000",
		LocalIP:    "::1",
		LocalPort:  "8080",
		RemoteIP:   "2001:db8::1",
		RemotePort: "9000",
	}

	hsErr.Connection = quicInfo
	verbose = hsErr.Verbose()
	t.Logf("QUIC connection error:\n%s", verbose)

	// Test pipe connection info
	pipeInfo := &ConnectionInfo{
		Protocol:   "pipe",
		LocalAddr:  "pipe",
		RemoteAddr: "pipe",
		LocalIP:    "pipe",
		RemoteIP:   "pipe",
		LocalPort:  "",
		RemotePort: "",
	}

	hsErr.Connection = pipeInfo
	verbose = hsErr.Verbose()
	t.Logf("Pipe connection error:\n%s", verbose)
}

func TestErrorHierarchy(t *testing.T) {
	// Test that all error types implement the VerboseError interface
	hsErr := &HandshakeError{State: HandshakeStateInit, Message: "test"}
	pvErr := &ProtocolVersionError{Expected: []byte{0x03}, Received: []byte{0x02}}
	authErr := &AuthenticationError{}

	// Test VerboseError interface
	var _ VerboseError = hsErr
	var _ VerboseError = pvErr
	var _ VerboseError = authErr

	t.Log("All error types implement VerboseError interface")
}
