// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"bytes"
	"errors"
)

// The NIKE and sealed box methods ask the daemon to do the cryptography,
// with no mixnet IO, so the thin client needs none of its own. nikeScheme
// names an hpqc NIKE, e.g. "X25519-CTIDH1024". Keys are opaque bytes.

// NIKEGenerateKeyPair generates a NIKE keypair, returning its public and
// private keys.
func (t *ThinClient) NIKEGenerateKeyPair(nikeScheme string) ([]byte, []byte, error) {
	queryID := t.NewQueryID()
	ev, err := t.localQuery(queryID, &Request{NIKEGenerateKeyPair: &NIKEGenerateKeyPair{
		QueryID:    queryID,
		NIKEScheme: nikeScheme,
	}}, func(e Event) (*[QueryIDLength]byte, uint8, bool) {
		v, ok := e.(*NIKEGenerateKeyPairReply)
		if !ok {
			return nil, 0, false
		}
		return v.QueryID, v.ErrorCode, true
	})
	if err != nil {
		return nil, nil, err
	}
	reply := ev.(*NIKEGenerateKeyPairReply)
	return reply.PublicKey, reply.PrivateKey, nil
}

// NIKEDeriveSecret derives the shared secret of privateKey and the peer's
// publicKey. A degenerate (all zero) secret is an error.
func (t *ThinClient) NIKEDeriveSecret(nikeScheme string, privateKey, publicKey []byte) ([]byte, error) {
	queryID := t.NewQueryID()
	ev, err := t.localQuery(queryID, &Request{NIKEDeriveSecret: &NIKEDeriveSecret{
		QueryID:    queryID,
		NIKEScheme: nikeScheme,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}}, func(e Event) (*[QueryIDLength]byte, uint8, bool) {
		v, ok := e.(*NIKEDeriveSecretReply)
		if !ok {
			return nil, 0, false
		}
		return v.QueryID, v.ErrorCode, true
	})
	if err != nil {
		return nil, err
	}
	return ev.(*NIKEDeriveSecretReply).SharedSecret, nil
}

// BoxSeal seals plaintext to a NIKE public key with hpqc protocols/sealedbox.
func (t *ThinClient) BoxSeal(nikeScheme string, publicKey, plaintext []byte) ([]byte, error) {
	queryID := t.NewQueryID()
	ev, err := t.localQuery(queryID, &Request{BoxSeal: &BoxSeal{
		QueryID:    queryID,
		NIKEScheme: nikeScheme,
		PublicKey:  publicKey,
		Plaintext:  plaintext,
	}}, func(e Event) (*[QueryIDLength]byte, uint8, bool) {
		v, ok := e.(*BoxSealReply)
		if !ok {
			return nil, 0, false
		}
		return v.QueryID, v.ErrorCode, true
	})
	if err != nil {
		return nil, err
	}
	return ev.(*BoxSealReply).Ciphertext, nil
}

// BoxOpen opens a box sealed with BoxSeal, with the recipient's NIKE private
// key.
func (t *ThinClient) BoxOpen(nikeScheme string, privateKey, ciphertext []byte) ([]byte, error) {
	queryID := t.NewQueryID()
	ev, err := t.localQuery(queryID, &Request{BoxOpen: &BoxOpen{
		QueryID:    queryID,
		NIKEScheme: nikeScheme,
		PrivateKey: privateKey,
		Ciphertext: ciphertext,
	}}, func(e Event) (*[QueryIDLength]byte, uint8, bool) {
		v, ok := e.(*BoxOpenReply)
		if !ok {
			return nil, 0, false
		}
		return v.QueryID, v.ErrorCode, true
	})
	if err != nil {
		return nil, err
	}
	return ev.(*BoxOpenReply).Plaintext, nil
}

// localQuery sends req and waits for the reply that match recognises with
// queryID, returning an error for a reply that carries one.
func (t *ThinClient) localQuery(queryID *[QueryIDLength]byte, req *Request, match func(Event) (*[QueryIDLength]byte, uint8, bool)) (Event, error) {
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
		if v, ok := event.(*ConnectionStatusEvent); ok {
			t.setConnected(v.IsConnected)
			continue
		}
		id, code, ok := match(event)
		if !ok || id == nil || !bytes.Equal(id[:], queryID[:]) {
			continue
		}
		if code != ThinClientSuccess {
			return nil, errors.New(ThinClientErrorToString(code))
		}
		return event, nil
	}
}
