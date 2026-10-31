// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"context"
	"errors"

	"github.com/katzenpost/hpqc/bacap"
)

var (
	// ErrBoxNotFound reports a read of a box nobody has written yet.
	ErrBoxNotFound = errors.New("pigeonservice: box not found")
	// ErrTombstone reports a read of a box its owner tombstoned.
	ErrTombstone = errors.New("pigeonservice: box is a tombstone")
)

// ServiceNode is one instance of a mixnet service in the PKI.
type ServiceNode struct {
	NodeIDHash [32]byte
	Endpoint   []byte
	// Params is what the service published in the PKI.
	Params map[string]any
}

// MintResult is the outcome of minting a contact voucher.
type MintResult struct {
	Voucher         []byte
	Payload         []byte
	VoucherWriteCap []byte
	VoucherReadCap  []byte
	SecretKey       []byte
}

// InductResult is the outcome of inducting a contact voucher.
type InductResult struct {
	// MutatedReadCap reads the joiner's real messages.
	MutatedReadCap  []byte
	SealedReply     []byte
	VoucherWriteCap []byte
}

// OpenResult is the outcome of opening an inductor's sealed reply.
type OpenResult struct {
	WhoReply []byte
	// MutatedWriteCap writes the joiner's real messages.
	MutatedWriteCap []byte
}

// Pigeonhole is everything pigeonhole services need from the mixnet. The
// thin client provides it through NewThinPigeonhole; tests use an in-memory
// implementation.
type Pigeonhole interface {
	// NewStream creates a fresh stream.
	NewStream() (*bacap.WriteCap, *bacap.ReadCap, *bacap.MessageBoxIndex, error)
	// Write writes one box and returns the index after it. Writing a box
	// that already holds the same data succeeds.
	Write(ctx context.Context, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, plaintext []byte) (*bacap.MessageBoxIndex, error)
	// Read reads one box once, without waiting for it to be written, and
	// returns its plaintext and the index after it. It returns
	// ErrBoxNotFound or ErrTombstone for those outcomes.
	Read(ctx context.Context, readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex) ([]byte, *bacap.MessageBoxIndex, error)
	// Tombstone overwrites one box with a tombstone.
	Tombstone(ctx context.Context, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex) error
	// WritePayload writes payload across as many boxes as it needs,
	// starting at idx, all at once with a copy command, and returns the
	// index after the last box.
	WritePayload(ctx context.Context, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, payload []byte) (*bacap.MessageBoxIndex, error)
	// MaxPlaintext is the largest plaintext one box holds.
	MaxPlaintext() int

	VoucherMint(messageWriteCap []byte, displayName string) (*MintResult, error)
	VoucherInduct(voucher, payload, whoReply []byte) (*InductResult, error)
	VoucherOpen(secretKey, sealedReply, messageWriteCap []byte) (*OpenResult, error)
	VoucherDeriveStream(voucher []byte) (writeCap, readCap []byte, err error)

	// BoxSeal seals plaintext to a NIKE public key.
	BoxSeal(nikeScheme string, publicKey, plaintext []byte) ([]byte, error)

	// Request sends payload to a mixnet service and returns its reply,
	// retransmitting until one arrives or ctx ends.
	Request(ctx context.Context, node *[32]byte, endpoint []byte, payload []byte) ([]byte, error)
	// Services lists the instances of a mixnet service in the PKI.
	Services(capability string) ([]ServiceNode, error)
}
