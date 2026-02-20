package thin

import (
	"context"
	"fmt"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/util"

	phgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

func TombstonePlaintext(g *phgeo.Geometry) ([]byte, error) {
	if g == nil {
		return nil, fmt.Errorf("nil geometry")
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return make([]byte, g.MaxPlaintextPayloadLength), nil
}

func IsTombstonePlaintext(g *phgeo.Geometry, plaintext []byte) bool {
	if g == nil {
		return false
	}
	if len(plaintext) != int(g.MaxPlaintextPayloadLength) {
		return false
	}
	return util.CtIsZero(plaintext)
}

func (c *ThinClient) TombstoneBox(
	ctx context.Context,
	g *phgeo.Geometry,
	writeCap *bacap.WriteCap,
	boxIndex *bacap.MessageBoxIndex,
) error {

	if g == nil {
		return fmt.Errorf("nil geometry")
	}
	if err := g.Validate(); err != nil {
		return err
	}

	tomb := make([]byte, g.MaxPlaintextPayloadLength)

	// EncryptWrite returns: messageCiphertext, envelopeDescriptor, envelopeHash, replicaEpoch, error
	messageCiphertext, envelopeDescriptor, envelopeHash, replicaEpoch, err := c.EncryptWrite(ctx, tomb, writeCap, boxIndex)
	if err != nil {
		return fmt.Errorf("EncryptWrite failed: %w", err)
	}

	// Tombstoning is a write operation, so readCap must be nil
	_, err = c.StartResendingEncryptedMessage(
		ctx,
		nil, // readCap - nil for write operations
		writeCap,
		nil, // nextMessageIndex - not needed for writes
		nil, // replyIndex - not needed for writes
		envelopeDescriptor,
		messageCiphertext,
		envelopeHash,
		replicaEpoch,
	)
	if err != nil {
		return fmt.Errorf("StartResendingEncryptedMessage failed: %w", err)
	}

	return nil
}

type TombstoneRangeResult struct {
	Tombstoned uint32
	Next       *bacap.MessageBoxIndex
}

func (c *ThinClient) TombstoneRange(
	ctx context.Context,
	g *phgeo.Geometry,
	writeCap *bacap.WriteCap,
	start *bacap.MessageBoxIndex,
	maxCount uint32,
) (*TombstoneRangeResult, error) {

	if g == nil {
		return nil, fmt.Errorf("nil geometry")
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	if writeCap == nil {
		return nil, fmt.Errorf("nil writeCap")
	}
	if start == nil {
		return nil, fmt.Errorf("nil start index")
	}
	if maxCount == 0 {
		return &TombstoneRangeResult{Tombstoned: 0, Next: start}, nil
	}

	tomb := make([]byte, g.MaxPlaintextPayloadLength)

	// Derive ReadCap from WriteCap
	readCap := writeCap.ReadCap()

	cur := start
	var done uint32

	for done < maxCount {
		// EncryptWrite returns: messageCiphertext, envelopeDescriptor, envelopeHash, replicaEpoch, error
		messageCiphertext, envelopeDescriptor, envelopeHash, replicaEpoch, err := c.EncryptWrite(ctx, tomb, writeCap, cur)
		if err != nil {
			return &TombstoneRangeResult{Tombstoned: done, Next: cur},
				fmt.Errorf("EncryptWrite failed: %w", err)
		}

		// StartResendingEncryptedMessage returns: plaintext, error
		_, err = c.StartResendingEncryptedMessage(
			ctx,
			readCap,
			writeCap,
			nil, // nextMessageIndex - not needed for tombstoning
			nil, // replyIndex
			envelopeDescriptor,
			messageCiphertext,
			envelopeHash,
			replicaEpoch,
		)
		if err != nil {
			return &TombstoneRangeResult{Tombstoned: done, Next: cur},
				fmt.Errorf("StartResendingEncryptedMessage failed: %w", err)
		}

		done++

		// Advance to next message box index
		next, err := cur.NextIndex()
		if err != nil {
			return &TombstoneRangeResult{Tombstoned: done, Next: cur}, err
		}
		cur = next
	}

	return &TombstoneRangeResult{Tombstoned: done, Next: cur}, nil
}
