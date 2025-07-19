// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"fmt"
	"strings"

	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
)

// HandshakeState represents the current state of the handshake
type HandshakeState string

const (
	HandshakeStateInit           HandshakeState = "initialization"
	HandshakeStateMsg1Send       HandshakeState = "message_1_send"
	HandshakeStateMsg1Receive    HandshakeState = "message_1_receive"
	HandshakeStateMsg2Send       HandshakeState = "message_2_send"
	HandshakeStateMsg2Receive    HandshakeState = "message_2_receive"
	HandshakeStateMsg3Send       HandshakeState = "message_3_send"
	HandshakeStateMsg3Receive    HandshakeState = "message_3_receive"
	HandshakeStateMsg4Send       HandshakeState = "message_4_send"
	HandshakeStateMsg4Receive    HandshakeState = "message_4_receive"
	HandshakeStateAuthentication HandshakeState = "peer_authentication"
	HandshakeStateFinalization   HandshakeState = "finalization"
)

// ConnectionInfo provides detailed network connection information
type ConnectionInfo struct {
	Protocol   string // "tcp", "tcp4", "tcp6", "quic", "udp", etc.
	LocalAddr  string // Local IP:port
	RemoteAddr string // Remote IP:port
	LocalIP    string // Local IP address only
	RemoteIP   string // Remote IP address only
	LocalPort  string // Local port only
	RemotePort string // Remote port only
}

// HandshakeError provides comprehensive information about handshake failures
type HandshakeError struct {
	State           HandshakeState
	Message         string
	UnderlyingError error
	IsInitiator     bool

	// Key material information
	LocalStaticKey  kem.PublicKey
	RemoteStaticKey kem.PublicKey

	// Protocol information
	ProtocolName string
	KEMScheme    string

	// Message information
	MessageNumber int
	MessageSize   int
	ExpectedSize  int

	// Authentication information
	AdditionalData  []byte
	PeerCredentials *PeerCredentials

	// Network information
	Connection *ConnectionInfo
}

// Error implements the error interface
func (e *HandshakeError) Error() string {
	var b strings.Builder

	// Basic error information
	fmt.Fprintf(&b, "wire/session: handshake failed at %s", e.State)
	if e.IsInitiator {
		b.WriteString(" (initiator)")
	} else {
		b.WriteString(" (responder)")
	}

	if e.Connection != nil && e.Connection.RemoteAddr != "" {
		fmt.Fprintf(&b, " with peer %s (%s)", e.Connection.RemoteAddr, e.Connection.Protocol)
	}

	fmt.Fprintf(&b, ": %s", e.Message)

	if e.UnderlyingError != nil {
		fmt.Fprintf(&b, " (underlying error: %v)", e.UnderlyingError)
	}

	return b.String()
}

// Verbose returns a detailed error message with all available information
func (e *HandshakeError) Verbose() string {
	var b strings.Builder

	// Header
	b.WriteString("=== WIRE PROTOCOL HANDSHAKE FAILURE ===\n")

	// Basic information
	fmt.Fprintf(&b, "State: %s\n", e.State)
	fmt.Fprintf(&b, "Role: ")
	if e.IsInitiator {
		b.WriteString("initiator (client)\n")
	} else {
		b.WriteString("responder (server)\n")
	}

	if e.Connection != nil {
		b.WriteString("\n--- CONNECTION INFORMATION ---\n")
		fmt.Fprintf(&b, "Protocol: %s\n", e.Connection.Protocol)
		fmt.Fprintf(&b, "Local Address: %s (%s:%s)\n", e.Connection.LocalAddr, e.Connection.LocalIP, e.Connection.LocalPort)
		fmt.Fprintf(&b, "Remote Address: %s (%s:%s)\n", e.Connection.RemoteAddr, e.Connection.RemoteIP, e.Connection.RemotePort)
	}

	fmt.Fprintf(&b, "Error Message: %s\n", e.Message)

	if e.UnderlyingError != nil {
		fmt.Fprintf(&b, "Underlying Error: %v\n", e.UnderlyingError)
	}

	// Protocol information
	b.WriteString("\n--- PROTOCOL INFORMATION ---\n")
	fmt.Fprintf(&b, "Protocol: %s\n", e.ProtocolName)
	fmt.Fprintf(&b, "KEM Scheme: %s\n", e.KEMScheme)

	// Message information
	if e.MessageNumber > 0 {
		b.WriteString("\n--- MESSAGE INFORMATION ---\n")
		fmt.Fprintf(&b, "Message Number: %d\n", e.MessageNumber)
		if e.MessageSize > 0 {
			fmt.Fprintf(&b, "Message Size: %d bytes\n", e.MessageSize)
		}
		if e.ExpectedSize > 0 {
			fmt.Fprintf(&b, "Expected Size: %d bytes\n", e.ExpectedSize)
		}
	}

	// Key material
	b.WriteString("\n--- KEY MATERIAL ---\n")
	if e.LocalStaticKey != nil {
		fmt.Fprintf(&b, "Local Static Key: %s\n", strings.TrimSpace(kempem.ToPublicPEMString(e.LocalStaticKey)))
	}
	if e.RemoteStaticKey != nil {
		fmt.Fprintf(&b, "Remote Static Key: %s\n", strings.TrimSpace(kempem.ToPublicPEMString(e.RemoteStaticKey)))
	}

	// Authentication information
	if e.AdditionalData != nil || e.PeerCredentials != nil {
		b.WriteString("\n--- AUTHENTICATION INFORMATION ---\n")
		if e.AdditionalData != nil {
			fmt.Fprintf(&b, "Additional Data: %x\n", e.AdditionalData)
		}
		if e.PeerCredentials != nil {
			fmt.Fprintf(&b, "Peer Additional Data: %x\n", e.PeerCredentials.AdditionalData)
			if e.PeerCredentials.PublicKey != nil {
				fmt.Fprintf(&b, "Peer Public Key: %s\n", strings.TrimSpace(kempem.ToPublicPEMString(e.PeerCredentials.PublicKey)))
			}
		}
	}

	b.WriteString("=== END HANDSHAKE FAILURE ===")

	return b.String()
}

// NewHandshakeError creates a new HandshakeError with the given parameters
func NewHandshakeError(state HandshakeState, message string, err error) *HandshakeError {
	return &HandshakeError{
		State:           state,
		Message:         message,
		UnderlyingError: err,
	}
}

// ProtocolVersionError represents a protocol version mismatch
type ProtocolVersionError struct {
	Expected   []byte
	Received   []byte
	Connection *ConnectionInfo
}

func (e *ProtocolVersionError) Error() string {
	if e.Connection != nil {
		return fmt.Sprintf("wire/session: protocol version mismatch: expected %x, received %x from %s (%s)",
			e.Expected, e.Received, e.Connection.RemoteAddr, e.Connection.Protocol)
	}
	return fmt.Sprintf("wire/session: protocol version mismatch: expected %x, received %x",
		e.Expected, e.Received)
}

func (e *ProtocolVersionError) Verbose() string {
	var b strings.Builder
	b.WriteString("=== PROTOCOL VERSION MISMATCH ===\n")
	fmt.Fprintf(&b, "Expected Version: %x\n", e.Expected)
	fmt.Fprintf(&b, "Received Version: %x\n", e.Received)

	if e.Connection != nil {
		b.WriteString("\n--- CONNECTION INFORMATION ---\n")
		fmt.Fprintf(&b, "Protocol: %s\n", e.Connection.Protocol)
		fmt.Fprintf(&b, "Local Address: %s (%s:%s)\n", e.Connection.LocalAddr, e.Connection.LocalIP, e.Connection.LocalPort)
		fmt.Fprintf(&b, "Remote Address: %s (%s:%s)\n", e.Connection.RemoteAddr, e.Connection.RemoteIP, e.Connection.RemotePort)
	}

	b.WriteString("=== END VERSION MISMATCH ===")
	return b.String()
}

// AuthenticationError represents a peer authentication failure
type AuthenticationError struct {
	PeerCredentials *PeerCredentials
	AdditionalData  []byte
	Connection      *ConnectionInfo
	ClockSkew       int64
}

func (e *AuthenticationError) Error() string {
	if e.Connection != nil {
		return fmt.Sprintf("wire/session: peer authentication failed from %s (%s)",
			e.Connection.RemoteAddr, e.Connection.Protocol)
	}
	return "wire/session: peer authentication failed"
}

func (e *AuthenticationError) Verbose() string {
	var b strings.Builder
	b.WriteString("=== PEER AUTHENTICATION FAILURE ===\n")

	if e.Connection != nil {
		b.WriteString("\n--- CONNECTION INFORMATION ---\n")
		fmt.Fprintf(&b, "Protocol: %s\n", e.Connection.Protocol)
		fmt.Fprintf(&b, "Local Address: %s (%s:%s)\n", e.Connection.LocalAddr, e.Connection.LocalIP, e.Connection.LocalPort)
		fmt.Fprintf(&b, "Remote Address: %s (%s:%s)\n", e.Connection.RemoteAddr, e.Connection.RemoteIP, e.Connection.RemotePort)
	}

	if e.ClockSkew != 0 {
		fmt.Fprintf(&b, "Clock Skew: %d seconds\n", e.ClockSkew)
	}

	b.WriteString("\n--- LOCAL CREDENTIALS ---\n")
	if e.AdditionalData != nil {
		fmt.Fprintf(&b, "Additional Data: %x\n", e.AdditionalData)
	}

	b.WriteString("\n--- PEER CREDENTIALS ---\n")
	if e.PeerCredentials != nil {
		fmt.Fprintf(&b, "Additional Data: %x\n", e.PeerCredentials.AdditionalData)
		if e.PeerCredentials.PublicKey != nil {
			fmt.Fprintf(&b, "Public Key: %s\n", strings.TrimSpace(kempem.ToPublicPEMString(e.PeerCredentials.PublicKey)))
		}
	}

	b.WriteString("=== END AUTHENTICATION FAILURE ===")
	return b.String()
}

// MessageSizeError represents a message size validation error
type MessageSizeError struct {
	MessageNumber int
	ActualSize    int
	ExpectedSize  int
	MaxSize       int
	State         HandshakeState
}

func (e *MessageSizeError) Error() string {
	return fmt.Sprintf("wire/session: message %d size error at %s: got %d bytes, expected %d bytes",
		e.MessageNumber, e.State, e.ActualSize, e.ExpectedSize)
}

func (e *MessageSizeError) Verbose() string {
	var b strings.Builder
	b.WriteString("=== MESSAGE SIZE ERROR ===\n")
	fmt.Fprintf(&b, "Handshake State: %s\n", e.State)
	fmt.Fprintf(&b, "Message Number: %d\n", e.MessageNumber)
	fmt.Fprintf(&b, "Actual Size: %d bytes\n", e.ActualSize)
	fmt.Fprintf(&b, "Expected Size: %d bytes\n", e.ExpectedSize)
	if e.MaxSize > 0 {
		fmt.Fprintf(&b, "Maximum Allowed: %d bytes\n", e.MaxSize)
	}
	b.WriteString("=== END MESSAGE SIZE ERROR ===")
	return b.String()
}

// VerboseError interface for errors that can provide detailed information
type VerboseError interface {
	error
	Verbose() string
}

// IsHandshakeError checks if an error is a HandshakeError
func IsHandshakeError(err error) bool {
	_, ok := err.(*HandshakeError)
	return ok
}

// IsProtocolVersionError checks if an error is a ProtocolVersionError
func IsProtocolVersionError(err error) bool {
	_, ok := err.(*ProtocolVersionError)
	return ok
}

// IsAuthenticationError checks if an error is an AuthenticationError
func IsAuthenticationError(err error) bool {
	_, ok := err.(*AuthenticationError)
	return ok
}

// IsMessageSizeError checks if an error is a MessageSizeError
func IsMessageSizeError(err error) bool {
	_, ok := err.(*MessageSizeError)
	return ok
}

// GetVerboseError returns verbose error information if available
func GetVerboseError(err error) string {
	if ve, ok := err.(VerboseError); ok {
		return ve.Verbose()
	}
	return err.Error()
}

// GetHandshakeError returns the HandshakeError if the error is one
func GetHandshakeError(err error) (*HandshakeError, bool) {
	he, ok := err.(*HandshakeError)
	return he, ok
}

// ExtractConnectionInfo extracts detailed connection information from net.Conn
func ExtractConnectionInfo(conn interface{}) *ConnectionInfo {
	if conn == nil {
		return nil
	}

	// Use type assertion to check for the standard net.Conn interface
	// This should work with any type that implements net.Conn
	type netConn interface {
		LocalAddr() interface {
			Network() string
			String() string
		}
		RemoteAddr() interface {
			Network() string
			String() string
		}
	}

	if c, ok := conn.(netConn); ok {
		localAddr := c.LocalAddr()
		remoteAddr := c.RemoteAddr()

		if localAddr != nil && remoteAddr != nil {
			return buildConnectionInfo(localAddr.Network(), localAddr.String(), remoteAddr.String())
		}
	}

	return nil
}

// buildConnectionInfo creates a ConnectionInfo from the basic address information
func buildConnectionInfo(protocol, localAddrStr, remoteAddrStr string) *ConnectionInfo {
	// Special case for pipe connections
	if protocol == "pipe" {
		return &ConnectionInfo{
			Protocol:   "pipe",
			LocalAddr:  "pipe",
			RemoteAddr: "pipe",
			LocalIP:    "pipe",
			RemoteIP:   "pipe",
			LocalPort:  "",
			RemotePort: "",
		}
	}

	info := &ConnectionInfo{
		Protocol:   protocol,
		LocalAddr:  localAddrStr,
		RemoteAddr: remoteAddrStr,
	}

	// Extract IP and port from addresses
	if host, port, err := parseHostPort(info.LocalAddr); err == nil {
		info.LocalIP = host
		info.LocalPort = port
	}

	if host, port, err := parseHostPort(info.RemoteAddr); err == nil {
		info.RemoteIP = host
		info.RemotePort = port
	}

	return info
}

// parseHostPort splits a network address into host and port
func parseHostPort(addr string) (host, port string, err error) {
	// Handle IPv6 addresses with brackets
	if len(addr) > 0 && addr[0] == '[' {
		// IPv6 address like [::1]:8080
		end := strings.Index(addr, "]:")
		if end != -1 {
			return addr[1:end], addr[end+2:], nil
		}
		// IPv6 address without port like [::1]
		if addr[len(addr)-1] == ']' {
			return addr[1 : len(addr)-1], "", nil
		}
	}

	// Handle IPv4 addresses and hostnames
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		// No port
		return addr, "", nil
	}

	// Check if this might be an IPv6 address without brackets
	if strings.Count(addr, ":") > 1 && lastColon != strings.Index(addr, ":") {
		// Multiple colons, likely IPv6 without brackets
		return addr, "", nil
	}

	return addr[:lastColon], addr[lastColon+1:], nil
}
