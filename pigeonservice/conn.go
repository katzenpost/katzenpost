// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/katzenpost/hpqc/bacap"
)

// ErrMessageTooLarge reports a message larger than one box.
var ErrMessageTooLarge = errors.New("pigeonservice: message larger than one box")

// Conn is a two-way Pigeonhole connection: a stream this side writes and a
// stream the peer writes. Send and Recv may be called concurrently with each
// other, but each from one goroutine at a time.
type Conn struct {
	ph           Pigeonhole
	pollInterval time.Duration

	sendMu   sync.Mutex
	writeCap *bacap.WriteCap
	writeIdx *bacap.MessageBoxIndex
	sent     []sentBox

	recvMu  sync.Mutex
	readCap *bacap.ReadCap
	readIdx *bacap.MessageBoxIndex
}

type sentBox struct {
	Index     []byte
	Plaintext []byte
	At        time.Time
}

func newConn(ph Pigeonhole, wc *bacap.WriteCap, widx *bacap.MessageBoxIndex, rc *bacap.ReadCap, ridx *bacap.MessageBoxIndex, pollInterval time.Duration) *Conn {
	return &Conn{
		ph:           ph,
		pollInterval: pollInterval,
		writeCap:     wc,
		writeIdx:     widx,
		readCap:      rc,
		readIdx:      ridx,
	}
}

// Send writes msg to the next box of this side's stream.
func (c *Conn) Send(ctx context.Context, msg []byte) error {
	if len(msg) == 0 {
		return errors.New("pigeonservice: empty message")
	}
	if len(msg) > c.ph.MaxPlaintext() {
		return ErrMessageTooLarge
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	next, err := WriteRetry(ctx, c.ph, c.writeCap, c.writeIdx, msg)
	if err != nil {
		return err
	}
	idx, err := c.writeIdx.MarshalBinary()
	if err != nil {
		return err
	}
	c.sent = append(c.sent, sentBox{Index: idx, Plaintext: msg, At: time.Now()})
	c.writeIdx = next
	return nil
}

// Recv waits for the peer's next message. Tombstoned boxes are skipped.
func (c *Conn) Recv(ctx context.Context) ([]byte, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	for {
		msg, next, err := ReadWait(ctx, c.ph, c.readCap, c.readIdx, c.pollInterval)
		if errors.Is(err, ErrTombstone) {
			c.readIdx = next
			continue
		}
		if err != nil {
			return nil, err
		}
		c.readIdx = next
		return msg, nil
	}
}

// Refresh rewrites every box sent within retention, restoring any a replica
// has garbage-collected, and forgets older ones. Pigeonhole keeps a box for
// one to two replica epochs; calling Refresh once a replica epoch keeps a
// box readable for as long as retention allows. Rewrites are idempotent.
func (c *Conn) Refresh(ctx context.Context, retention time.Duration) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	cutoff := time.Now().Add(-retention)
	kept := c.sent[:0]
	for _, b := range c.sent {
		if b.At.Before(cutoff) {
			continue
		}
		kept = append(kept, b)
	}
	c.sent = kept
	for _, b := range c.sent {
		idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(b.Index)
		if err != nil {
			return err
		}
		if _, err := c.ph.Write(ctx, c.writeCap, idx, b.Plaintext); err != nil {
			return err
		}
	}
	return nil
}

// ConnState is a Conn's persistent state.
type ConnState struct {
	WriteCap []byte
	WriteIdx []byte
	ReadCap  []byte
	ReadIdx  []byte
	Sent     []sentBox
}

// State returns the Conn's state for persistence.
func (c *Conn) State() (*ConnState, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	s := &ConnState{Sent: append([]sentBox(nil), c.sent...)}
	var err error
	if s.WriteCap, err = c.writeCap.MarshalBinary(); err != nil {
		return nil, err
	}
	if s.WriteIdx, err = c.writeIdx.MarshalBinary(); err != nil {
		return nil, err
	}
	if s.ReadCap, err = c.readCap.MarshalBinary(); err != nil {
		return nil, err
	}
	if s.ReadIdx, err = c.readIdx.MarshalBinary(); err != nil {
		return nil, err
	}
	return s, nil
}

// RestoreConn rebuilds a Conn from its persistent state.
func RestoreConn(ph Pigeonhole, s *ConnState, pollInterval time.Duration) (*Conn, error) {
	wc, err := bacap.NewWriteCapFromBytes(s.WriteCap)
	if err != nil {
		return nil, err
	}
	widx, err := bacap.NewEmptyMessageBoxIndexFromBytes(s.WriteIdx)
	if err != nil {
		return nil, err
	}
	rc, err := bacap.ReadCapFromBytes(s.ReadCap)
	if err != nil {
		return nil, err
	}
	ridx, err := bacap.NewEmptyMessageBoxIndexFromBytes(s.ReadIdx)
	if err != nil {
		return nil, err
	}
	c := newConn(ph, wc, widx, rc, ridx, pollInterval)
	c.sent = append([]sentBox(nil), s.Sent...)
	return c, nil
}
