// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// Advertiser publishes service descriptors where clients can find them.
type Advertiser interface {
	Advertise(ctx context.Context, d *common.ServiceDescriptor) error
	Withdraw(ctx context.Context, id common.ServiceID) error
}

// Discoverer finds service descriptors.
type Discoverer interface {
	Lookup(ctx context.Context, id common.ServiceID) (*common.ServiceDescriptor, error)
	List(ctx context.Context) ([]common.ServiceDescriptor, error)
}

// maxSnapshot bounds the size of a snapshot a reader accepts.
const maxSnapshot = 10 << 20

// EncodeSnapshot frames a snapshot for a stream: a 4-byte big-endian length
// followed by the snapshot's CBOR, split across as many boxes as it needs.
func EncodeSnapshot(s *Snapshot) ([]byte, error) {
	body, err := common.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(body) > maxSnapshot {
		return nil, errors.New("pigeonservice: snapshot too large")
	}
	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...), nil
}

// ReadSnapshot reads a snapshot from its stream, and the number of boxes it
// spans.
func ReadSnapshot(ctx context.Context, ph common.Pigeonhole, readCap *bacap.ReadCap, start *bacap.MessageBoxIndex, pollInterval time.Duration) (*Snapshot, int, error) {
	var buf []byte
	want := -1
	idx := start
	boxes := 0
	for want < 0 || len(buf) < 4+want {
		chunk, next, err := common.ReadWait(ctx, ph, readCap, idx, pollInterval)
		if err != nil {
			return nil, 0, err
		}
		boxes++
		buf = append(buf, chunk...)
		idx = next
		if want < 0 && len(buf) >= 4 {
			want = int(binary.BigEndian.Uint32(buf))
			if want > maxSnapshot {
				return nil, 0, errors.New("pigeonservice: snapshot too large")
			}
		}
	}
	var s Snapshot
	if err := common.Unmarshal(buf[4:4+want], &s); err != nil {
		return nil, 0, err
	}
	return &s, boxes, nil
}
