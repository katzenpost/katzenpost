package geo

import (
	"testing"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

// TestMeasureTrunnelOverhead measures the actual trunnel serialization overhead
func TestMeasureTrunnelOverhead(t *testing.T) {
	// Test CourierQuery overhead
	t.Run("CourierQuery", func(t *testing.T) {
		envelope := &pigeonhole.CourierEnvelope{
			SenderPubkeyLen: 32,                // Set the length field
			SenderPubkey:    make([]byte, 32),  // 32 bytes
			CiphertextLen:   100,               // 4 bytes
			Ciphertext:      make([]byte, 100), // 100 bytes
		}

		query := &pigeonhole.CourierQuery{
			QueryType: 0,        // 1 byte (discriminator)
			Envelope:  envelope, // embedded struct
		}

		// Calculate struct field sizes
		envelopeBytes := envelope.Bytes()
		structFieldSize := len(envelopeBytes) + 1 // envelope + QueryType (union discriminator)

		// Serialize and measure
		serialized := query.Bytes()
		actualSize := len(serialized)

		overhead := actualSize - structFieldSize

		t.Logf("CourierQuery struct fields: %d bytes", structFieldSize)
		t.Logf("CourierQuery serialized: %d bytes", actualSize)
		t.Logf("CourierQuery trunnel overhead: %d bytes", overhead)
	})

	// Test CourierEnvelope overhead
	t.Run("CourierEnvelope", func(t *testing.T) {
		envelope := &pigeonhole.CourierEnvelope{
			SenderPubkeyLen: 32,                // Set the length field
			SenderPubkey:    make([]byte, 32),  // 32 bytes
			CiphertextLen:   100,               // 4 bytes
			Ciphertext:      make([]byte, 100), // 100 bytes
		}

		// Calculate struct field sizes (just the variable-length fields)
		structFieldSize := 32 + 4 + 100 // SenderPubkey + CiphertextLen + Ciphertext

		// Serialize and measure
		serialized := envelope.Bytes()
		actualSize := len(serialized)

		overhead := actualSize - structFieldSize

		t.Logf("CourierEnvelope struct fields: %d bytes", structFieldSize)
		t.Logf("CourierEnvelope serialized: %d bytes", actualSize)
		t.Logf("CourierEnvelope trunnel overhead: %d bytes", overhead)
	})
}
