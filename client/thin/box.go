// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"bytes"
	"errors"
)

// BoxSeal seals plaintext to a NIKE public key with hpqc protocols/box.
// The daemon does the cryptography with no mixnet IO. nikeScheme names the
// recipient's NIKE, e.g. "X25519-CTIDH1024".
func (t *ThinClient) BoxSeal(nikeScheme string, publicKey, plaintext []byte) ([]byte, error) {
	queryID := t.NewQueryID()
	req := &Request{
		BoxSeal: &BoxSeal{
			QueryID:    queryID,
			NIKEScheme: nikeScheme,
			PublicKey:  publicKey,
			Plaintext:  plaintext,
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
		case *BoxSealReply:
			if v.QueryID == nil || !bytes.Equal(v.QueryID[:], queryID[:]) {
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.Ciphertext, nil
		case *ConnectionStatusEvent:
			t.setConnected(v.IsConnected)
		case *NewDocumentEvent:
		default:
		}
	}
}
