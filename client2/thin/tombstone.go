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
	if writeCap == nil {
		return fmt.Errorf("nil writeCap")
	}
	if boxIndex == nil {
		return fmt.Errorf("nil boxIndex")
	}

	tomb := make([]byte, g.MaxPlaintextPayloadLength)

	messageCiphertext, envelopeDescriptor, envelopeHash, replicaEpoch, err :=
		c.EncryptWrite(ctx, tomb, writeCap, boxIndex)
	if err != nil {
		return fmt.Errorf("EncryptWrite failed: %w", err)
	}

	_, err = c.StartResendingEncryptedMessage(
		ctx,
		nil,
		writeCap,
		nil,
		nil,
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

	cur := start
	var done uint32

	for done < maxCount {

		if err := c.TombstoneBox(ctx, g, writeCap, cur); err != nil {
			return &TombstoneRangeResult{
				Tombstoned: done,
				Next:       cur,
			}, err
		}

		done++

		next, err := cur.NextIndex()
		if err != nil {
			return &TombstoneRangeResult{
				Tombstoned: done,
				Next:       cur,
			}, err
		}
		cur = next
	}

	return &TombstoneRangeResult{
		Tombstoned: done,
		Next:       cur,
	}, nil
}
