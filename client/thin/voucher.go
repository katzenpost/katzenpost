// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"bytes"
	"errors"
)

// The Contact Voucher thin-client methods. Each sends a pure-crypto request
// to the daemon (which serves it from hpqc/voucher with no mixnet IO) and
// awaits the matching reply, correlated by QueryID. All capability and key
// material is opaque bytes; the thin client performs no cryptography. The
// returned reply struct carries the result fields; its QueryID and ErrorCode
// are internal bookkeeping.

// VoucherMint mints a Voucher from the joiner's MessageStream write cap. The
// returned reply carries the Voucher to hand over out of band, the payload to
// publish to VoucherStream box 0, the rendezvous stream caps, and the reply
// keypair; persist VoucherSecretKey to open the inductor's reply later.
func (t *ThinClient) VoucherMint(messageWriteCap []byte, displayName string) (*VoucherMintReply, error) {
	queryID := t.NewQueryID()
	req := &Request{
		VoucherMint: &VoucherMint{
			QueryID:         queryID,
			MessageWriteCap: messageWriteCap,
			DisplayName:     displayName,
		},
	}
	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	if err := t.writeMessage(req); err != nil {
		return nil, err
	}
	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}
		switch v := event.(type) {
		case *VoucherMintReply:
			if v.QueryID == nil || !bytes.Equal(v.QueryID[:], queryID[:]) {
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v, nil
		case *ConnectionStatusEvent:
			t.setConnected(v.IsConnected)
		case *NewDocumentEvent:
		default:
		}
	}
}

// VoucherInduct verifies a published VoucherPayload and seals a reply to the
// joiner. The returned reply carries the joiner's salt-mutated read cap (the
// live read cap to hand the group), the sealed reply to write to VoucherStream
// box 1, and the salt the inductor minted.
func (t *ThinClient) VoucherInduct(voucher, voucherPayload, whoReply []byte) (*VoucherInductReply, error) {
	queryID := t.NewQueryID()
	req := &Request{
		VoucherInduct: &VoucherInduct{
			QueryID:        queryID,
			Voucher:        voucher,
			VoucherPayload: voucherPayload,
			WhoReply:       whoReply,
		},
	}
	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	if err := t.writeMessage(req); err != nil {
		return nil, err
	}
	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}
		switch v := event.(type) {
		case *VoucherInductReply:
			if v.QueryID == nil || !bytes.Equal(v.QueryID[:], queryID[:]) {
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v, nil
		case *ConnectionStatusEvent:
			t.setConnected(v.IsConnected)
		case *NewDocumentEvent:
		default:
		}
	}
}

// VoucherOpen opens the inductor's sealed reply with the joiner's voucher
// secret key, recovers the salt, and mutates the joiner's MessageStream write
// cap by it. The returned reply carries the opaque WhoReply, the salt, and the
// salt-mutated write cap with which the joiner writes real messages.
func (t *ThinClient) VoucherOpen(voucherSecretKey, sealedReply, messageWriteCap []byte) (*VoucherOpenReply, error) {
	queryID := t.NewQueryID()
	req := &Request{
		VoucherOpen: &VoucherOpen{
			QueryID:          queryID,
			VoucherSecretKey: voucherSecretKey,
			SealedReply:      sealedReply,
			MessageWriteCap:  messageWriteCap,
		},
	}
	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	if err := t.writeMessage(req); err != nil {
		return nil, err
	}
	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}
		switch v := event.(type) {
		case *VoucherOpenReply:
			if v.QueryID == nil || !bytes.Equal(v.QueryID[:], queryID[:]) {
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v, nil
		case *ConnectionStatusEvent:
			t.setConnected(v.IsConnected)
		case *NewDocumentEvent:
		default:
		}
	}
}

// VoucherDeriveStream derives the VoucherStream caps from the Voucher, which
// the inductor needs to read box 0 before inducting.
func (t *ThinClient) VoucherDeriveStream(voucher []byte) (*VoucherDeriveStreamReply, error) {
	queryID := t.NewQueryID()
	req := &Request{
		VoucherDeriveStream: &VoucherDeriveStream{
			QueryID: queryID,
			Voucher: voucher,
		},
	}
	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	if err := t.writeMessage(req); err != nil {
		return nil, err
	}
	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}
		switch v := event.(type) {
		case *VoucherDeriveStreamReply:
			if v.QueryID == nil || !bytes.Equal(v.QueryID[:], queryID[:]) {
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v, nil
		case *ConnectionStatusEvent:
			t.setConnected(v.IsConnected)
		case *NewDocumentEvent:
		default:
		}
	}
}
