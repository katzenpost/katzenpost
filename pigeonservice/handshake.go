// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/katzenpost/hpqc/bacap"
)

// The contact voucher handshake. The joiner mints a voucher for its own
// stream and publishes the voucher payload in box 0 of the voucher stream.
// The inductor, holding the voucher, reads box 0, creates its own stream and
// writes a sealed reply naming that stream in box 1. The joiner opens box 1.
// Each side then writes its own stream and reads the other's.

// whoReply is the WhoReply an inductor seals for the joiner. It has the
// shape of the group chat ReplyWho with one member: the inductor.
type whoReply struct {
	PleaseAdds []pleaseAdd `cbor:"please_adds"`
}

type pleaseAdd struct {
	DisplayName string `cbor:"display_name"`
	ReadCap     []byte `cbor:"read_cap"`
}

// ErrBadWhoReply reports a WhoReply that does not name exactly one stream.
var ErrBadWhoReply = errors.New("pigeonservice: WhoReply must name exactly one stream")

func encodeWhoReply(displayName string, readCap *bacap.ReadCap) ([]byte, error) {
	rc, err := readCap.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return Marshal(&whoReply{PleaseAdds: []pleaseAdd{{DisplayName: displayName, ReadCap: rc}}})
}

func decodeWhoReply(b []byte) (*bacap.ReadCap, error) {
	var w whoReply
	if err := Unmarshal(b, &w); err != nil {
		return nil, err
	}
	if len(w.PleaseAdds) != 1 {
		return nil, ErrBadWhoReply
	}
	return bacap.ReadCapFromBytes(w.PleaseAdds[0].ReadCap)
}

// Pending is a minted voucher waiting for its inductor's reply.
type Pending struct {
	// Voucher is what the joiner hands to the inductor.
	Voucher []byte

	secretKey  []byte
	writeCap   []byte
	replyCap   *bacap.ReadCap
	replyIndex *bacap.MessageBoxIndex
}

// Mint creates the joiner's stream, mints a voucher for it, and publishes
// the voucher payload.
func Mint(ctx context.Context, ph Pigeonhole, displayName string) (*Pending, error) {
	wc, _, _, err := ph.NewStream()
	if err != nil {
		return nil, err
	}
	wcBytes, err := wc.MarshalBinary()
	if err != nil {
		return nil, err
	}
	m, err := ph.VoucherMint(wcBytes, displayName)
	if err != nil {
		return nil, err
	}
	vwc, err := bacap.NewWriteCapFromBytes(m.VoucherWriteCap)
	if err != nil {
		return nil, err
	}
	vrc, err := bacap.ReadCapFromBytes(m.VoucherReadCap)
	if err != nil {
		return nil, err
	}
	box1, err := WriteRetry(ctx, ph, vwc, vwc.GetMessageBoxIndex(), m.Payload)
	if err != nil {
		return nil, err
	}
	return &Pending{
		Voucher:    m.Voucher,
		secretKey:  m.SecretKey,
		writeCap:   wcBytes,
		replyCap:   vrc,
		replyIndex: box1,
	}, nil
}

// PendingState is the persistent form of a Pending. It holds the voucher's
// secret key: store it where only its owner can read it.
type PendingState struct {
	Voucher    []byte
	SecretKey  []byte
	WriteCap   []byte
	ReplyCap   []byte
	ReplyIndex []byte
}

// State returns the Pending's state for persistence.
func (p *Pending) State() (*PendingState, error) {
	s := &PendingState{Voucher: bytes.Clone(p.Voucher), SecretKey: bytes.Clone(p.secretKey), WriteCap: bytes.Clone(p.writeCap)}
	var err error
	if s.ReplyCap, err = p.replyCap.MarshalBinary(); err != nil {
		return nil, err
	}
	if s.ReplyIndex, err = p.replyIndex.MarshalBinary(); err != nil {
		return nil, err
	}
	return s, nil
}

// RestorePending rebuilds a Pending from its persistent state.
func RestorePending(s *PendingState) (*Pending, error) {
	rc, err := bacap.ReadCapFromBytes(s.ReplyCap)
	if err != nil {
		return nil, err
	}
	idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(s.ReplyIndex)
	if err != nil {
		return nil, err
	}
	return &Pending{
		Voucher:    bytes.Clone(s.Voucher),
		secretKey:  bytes.Clone(s.SecretKey),
		writeCap:   bytes.Clone(s.WriteCap),
		replyCap:   rc,
		replyIndex: idx,
	}, nil
}

// Await waits for the inductor's reply and returns the connection it opens.
func (p *Pending) Await(ctx context.Context, ph Pigeonhole, pollInterval time.Duration) (*Conn, error) {
	sealed, _, err := ReadWait(ctx, ph, p.replyCap, p.replyIndex, pollInterval)
	if err != nil {
		return nil, err
	}
	opened, err := ph.VoucherOpen(p.secretKey, sealed, p.writeCap)
	if err != nil {
		return nil, err
	}
	peer, err := decodeWhoReply(opened.WhoReply)
	if err != nil {
		return nil, err
	}
	wc, err := bacap.NewWriteCapFromBytes(opened.MutatedWriteCap)
	if err != nil {
		return nil, err
	}
	return newConn(ph, wc, wc.GetMessageBoxIndex(), peer, peer.GetMessageBoxIndex(), pollInterval), nil
}

// Induct reads the voucher payload, creates the inductor's stream, and
// writes the sealed reply naming it. It returns the connection to the
// joiner.
func Induct(ctx context.Context, ph Pigeonhole, voucher []byte, displayName string, pollInterval time.Duration) (*Conn, error) {
	vwcBytes, vrcBytes, err := ph.VoucherDeriveStream(voucher)
	if err != nil {
		return nil, err
	}
	vwc, err := bacap.NewWriteCapFromBytes(vwcBytes)
	if err != nil {
		return nil, err
	}
	vrc, err := bacap.ReadCapFromBytes(vrcBytes)
	if err != nil {
		return nil, err
	}
	box0 := vrc.GetMessageBoxIndex()
	payload, box1, err := ReadWait(ctx, ph, vrc, box0, pollInterval)
	if err != nil {
		return nil, err
	}

	wc, rc, first, err := ph.NewStream()
	if err != nil {
		return nil, err
	}
	who, err := encodeWhoReply(displayName, rc)
	if err != nil {
		return nil, err
	}
	inducted, err := ph.VoucherInduct(voucher, payload, who)
	if err != nil {
		return nil, err
	}
	peer, err := bacap.ReadCapFromBytes(inducted.MutatedReadCap)
	if err != nil {
		return nil, err
	}
	if _, err := WriteRetry(ctx, ph, vwc, box1, inducted.SealedReply); err != nil {
		return nil, err
	}
	// Box 0 is spent: tombstone it so the voucher cannot be inducted again,
	// which would open a session the joiner never learns of. The joiner
	// already has its reply, so the connection is returned either way.
	for ph.Tombstone(ctx, vwc, box0) != nil && sleep(ctx, retryInterval) == nil {
	}
	return newConn(ph, wc, first, peer, peer.GetMessageBoxIndex(), pollInterval), nil
}
