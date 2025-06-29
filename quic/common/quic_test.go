package common

import (
	"testing"

	"github.com/quic-go/quic-go"
)

func TestNewQuicConn(t *testing.T) {
	// Test that NewQuicConn panics with nil connection
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewQuicConn should panic with nil connection")
		}
	}()
	NewQuicConn(nil, &quic.Stream{})
}

func TestNewQuicConnNilStream(t *testing.T) {
	// Test that NewQuicConn panics with nil stream
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewQuicConn should panic with nil stream")
		}
	}()
	NewQuicConn(&quic.Conn{}, nil)
}

func TestQuicConnZeroValue(t *testing.T) {
	// Test that zero value QuicConn would panic on method calls
	// This demonstrates why the constructor is necessary
	var qc QuicConn
	
	// These would panic with nil pointer dereference before our fix
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Zero value QuicConn should panic on method calls")
		}
	}()
	
	// This should panic because Stream is nil
	qc.Read(make([]byte, 10))
}
