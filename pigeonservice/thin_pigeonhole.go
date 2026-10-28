// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/client/thin"
)

type thinPigeonhole struct {
	c *thin.ThinClient
}

// NewThinPigeonhole returns the Pigeonhole a connected thin client provides.
func NewThinPigeonhole(c *thin.ThinClient) Pigeonhole {
	return &thinPigeonhole{c: c}
}

func (p *thinPigeonhole) NewStream() (*bacap.WriteCap, *bacap.ReadCap, *bacap.MessageBoxIndex, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, nil, err
	}
	return p.c.NewKeypair(seed)
}

func (p *thinPigeonhole) Write(ctx context.Context, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, plaintext []byte) (*bacap.MessageBoxIndex, error) {
	ct, desc, envHash, next, err := p.c.EncryptWrite(plaintext, writeCap, idx)
	if err != nil {
		return nil, err
	}
	if _, err := p.c.StartResendingEncryptedMessageWithContext(ctx, nil, writeCap, nil, nil, desc, ct, envHash); err != nil {
		return nil, err
	}
	return next, nil
}

func (p *thinPigeonhole) Read(ctx context.Context, readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex) ([]byte, *bacap.MessageBoxIndex, error) {
	ct, desc, envHash, next, err := p.c.EncryptRead(readCap, idx)
	if err != nil {
		return nil, nil, err
	}
	idxBytes, err := idx.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	res, err := p.readNoRetry(ctx, readCap, idxBytes, desc, ct, envHash)
	switch {
	case errors.Is(err, thin.ErrBoxIDNotFound):
		return nil, nil, ErrBoxNotFound
	case errors.Is(err, thin.ErrTombstone):
		return nil, next, ErrTombstone
	case err != nil:
		return nil, nil, err
	}
	return res.Plaintext, next, nil
}

// readNoRetry is StartResendingEncryptedMessageNoRetry that also stops when
// ctx ends.
func (p *thinPigeonhole) readNoRetry(ctx context.Context, readCap *bacap.ReadCap, idx, desc, ct []byte, envHash *[32]byte) (*thin.StartResendingResult, error) {
	type result struct {
		res *thin.StartResendingResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := p.c.StartResendingEncryptedMessageNoRetry(readCap, nil, idx, nil, desc, ct, envHash)
		done <- result{res, err}
	}()
	select {
	case r := <-done:
		return r.res, r.err
	case <-ctx.Done():
		_ = p.c.CancelResendingEncryptedMessage(envHash)
		<-done
		return nil, ctx.Err()
	}
}

func (p *thinPigeonhole) Tombstone(ctx context.Context, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex) error {
	_, err := p.Write(ctx, writeCap, idx, []byte{})
	return err
}

func (p *thinPigeonhole) WritePayload(ctx context.Context, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, payload []byte) (*bacap.MessageBoxIndex, error) {
	chunks, next, err := p.c.CreateCourierEnvelopesFromPayload(payload, writeCap, idx, true, true)
	if err != nil {
		return nil, err
	}
	tempWriteCap, _, tempIdx, err := p.NewStream()
	if err != nil {
		return nil, err
	}
	for _, chunk := range chunks {
		if tempIdx, err = p.Write(ctx, tempWriteCap, tempIdx, chunk); err != nil {
			return nil, err
		}
	}
	if err := p.copyCommand(ctx, tempWriteCap); err != nil {
		return nil, err
	}
	return next, nil
}

func (p *thinPigeonhole) copyCommand(ctx context.Context, writeCap *bacap.WriteCap) error {
	done := make(chan error, 1)
	go func() {
		done <- p.c.StartResendingCopyCommand(writeCap)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		b, err := writeCap.MarshalBinary()
		if err == nil {
			h := hash.Sum256(b)
			_ = p.c.CancelResendingCopyCommand(&h)
		}
		<-done
		return ctx.Err()
	}
}

func (p *thinPigeonhole) MaxPlaintext() int {
	return p.c.GetPigeonholeGeometry().MaxPlaintextPayloadLength
}

func (p *thinPigeonhole) VoucherMint(messageWriteCap []byte, displayName string) (*MintResult, error) {
	r, err := p.c.VoucherMint(messageWriteCap, displayName)
	if err != nil {
		return nil, err
	}
	return &MintResult{
		Voucher:         r.Voucher,
		Payload:         r.VoucherPayload,
		VoucherWriteCap: r.VoucherWriteCap,
		VoucherReadCap:  r.VoucherReadCap,
		SecretKey:       r.VoucherSecretKey,
	}, nil
}

func (p *thinPigeonhole) VoucherInduct(voucher, payload, whoReply []byte) (*InductResult, error) {
	r, err := p.c.VoucherInduct(voucher, payload, whoReply)
	if err != nil {
		return nil, err
	}
	return &InductResult{
		MutatedReadCap:  r.MutatedMessageReadCap,
		SealedReply:     r.SealedReply,
		VoucherWriteCap: r.VoucherWriteCap,
	}, nil
}

func (p *thinPigeonhole) VoucherOpen(secretKey, sealedReply, messageWriteCap []byte) (*OpenResult, error) {
	r, err := p.c.VoucherOpen(secretKey, sealedReply, messageWriteCap)
	if err != nil {
		return nil, err
	}
	return &OpenResult{WhoReply: r.WhoReply, MutatedWriteCap: r.MutatedMessageWriteCap}, nil
}

func (p *thinPigeonhole) VoucherDeriveStream(voucher []byte) ([]byte, []byte, error) {
	r, err := p.c.VoucherDeriveStream(voucher)
	if err != nil {
		return nil, nil, err
	}
	return r.VoucherWriteCap, r.VoucherReadCap, nil
}

func (p *thinPigeonhole) BoxSeal(nikeScheme string, publicKey, plaintext []byte) ([]byte, error) {
	return p.c.BoxSeal(nikeScheme, publicKey, plaintext)
}

func (p *thinPigeonhole) Request(ctx context.Context, node *[32]byte, endpoint []byte, payload []byte) ([]byte, error) {
	return p.c.StartResendingMessage(ctx, node, endpoint, payload)
}

func (p *thinPigeonhole) Services(capability string) ([]ServiceNode, error) {
	descs, err := p.c.GetServices(capability)
	if err != nil {
		return nil, err
	}
	nodes := make([]ServiceNode, 0, len(descs))
	for _, d := range descs {
		nodes = append(nodes, ServiceNode{
			NodeIDHash: hash.Sum256(d.MixDescriptor.IdentityKey),
			Endpoint:   d.RecipientQueueID,
			Params:     d.MixDescriptor.Kaetzchen[capability],
		})
	}
	return nodes, nil
}
