// deaddrop.go - Deaddrop Kaetzchen.
// Copyright (C) 2018  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package kaetzchen

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/noise"
	"github.com/katzenpost/server/config"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/userdb"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

const (
	deaddropCapability = "deaddrop"
	deaddropVersion    = 0

	deaddropStatusOk          = 0
	deaddropStatusSyntaxError = 1
	deaddropStatusNoIdentity  = 2
	deaddropStatusAuthError   = 3
	deaddropStatusTempError   = 4

	deaddropAuthTokenLength = 32 + 16 // NoiseK pattern is -> e, es, ss
)

type deaddropRequest struct {
	Version   int
	User      string
	AuthToken string
	Command   string
	Sequence  int
}

type deaddropResponse struct {
	Version    int
	StatusCode int
	QueueHint  int
	Sequence   int
	Payload    string
}

type kaetzchenDeaddrop struct {
	log  *logging.Logger
	glue glue.Glue

	params     Parameters
	jsonHandle codec.JsonHandle

	userSequenceMap map[string]int
}

func (k *kaetzchenDeaddrop) Capability() string {
	return deaddropCapability
}

func (k *kaetzchenDeaddrop) Parameters() Parameters {
	return k.params
}

func (k *kaetzchenDeaddrop) decryptToken(token []byte, sender *ecdh.PublicKey, recipient *ecdh.PrivateKey) ([]byte, error) {
	if len(token) != deaddropAuthTokenLength {
		return nil, fmt.Errorf("block: invalid ciphertext length: %v (Expecting %v)", len(token), deaddropAuthTokenLength)
	}

	// Decrypt the ciphertext into a plaintext.
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	recipientDH := noise.DHKey{
		Private: recipient.Bytes(),
		Public:  recipient.PublicKey().Bytes(),
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeK,
		Initiator:     false,
		StaticKeypair: recipientDH,
		PeerStatic:    sender.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	plaintext, _, _, err := hs.ReadMessage(nil, token)
	if err != nil {
		return nil, err
	}

	return plaintext, err
}

func (k *kaetzchenDeaddrop) isAuthentic(authToken string, sender *ecdh.PublicKey, identityKey *ecdh.PrivateKey) bool {
	raw, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		k.log.Errorf("isAuthentic base64 decode failure: %s", err)
		return false
	}
	plaintext, err := k.decryptToken(raw, sender, identityKey)
	if plaintext != nil || err != nil {
		k.log.Errorf("isAuthentic decrypt token failure: %s", err)
		return false
	}
	return true
}

func (k *kaetzchenDeaddrop) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if !hasSURB {
		return nil, ErrNoResponse
	}

	k.log.Debugf("Handling request: %v", id)
	resp := deaddropResponse{
		Version:    deaddropVersion,
		StatusCode: deaddropStatusSyntaxError,
	}

	// Parse out the request payload.
	var req deaddropRequest
	dec := codec.NewDecoderBytes(bytes.TrimRight(payload, "\x00"), &k.jsonHandle)
	if err := dec.Decode(&req); err != nil {
		k.log.Debugf("Failed to decode request: %v (%v)", id, err)
		return k.encodeResp(&resp), nil
	}
	if req.Version != deaddropVersion {
		k.log.Debugf("Failed to parse request: %v (invalid version: %v)", id, req.Version)
		return k.encodeResp(&resp), nil
	}

	// Query the public key.
	sender, err := k.glue.Provider().UserDB().Identity([]byte(req.User))
	switch err {
	case nil:
		resp.StatusCode = deaddropStatusOk
		if k.glue.Provider().Spool() == nil {
			k.log.Error("impossible failure: Provider has nil spool reference")
			resp.StatusCode = deaddropStatusTempError
			break
		}

		// Authenticate client.
		if !k.isAuthentic(req.AuthToken, sender, k.glue.LinkKey()) {
			k.log.Errorf("Deaddrop client %s failed to authenticate", req.User)
			resp.StatusCode = deaddropStatusAuthError
			break
		}

		// Retrieve a message.
		sequence, ok := k.userSequenceMap[req.User]
		msg := []byte{}
		remaining := 0
		if !ok {
			msg, _, remaining, err = k.glue.Provider().Spool().Get([]byte(req.User), false)
			if err != nil {
				k.log.Errorf("KaetzenDeaddrop failure: %s", err)
			}
			resp.Sequence = 1
			k.userSequenceMap[req.User] = 1
		} else {
			if req.Sequence == sequence {
				_, _, _, err = k.glue.Provider().Spool().Get([]byte(req.User), true)
				if err != nil {
					k.log.Errorf("KaetzenDeaddrop failure: %s", err)
				}
				msg, _, remaining, err = k.glue.Provider().Spool().Get([]byte(req.User), false)
				if err != nil {
					k.log.Errorf("KaetzenDeaddrop failure: %s", err)
				}
				resp.Sequence = sequence + 1
				k.userSequenceMap[req.User] = resp.Sequence
			} else {
				k.log.Debugf("KaetzenDeaddrop sequence mismatch for user %s", req.User)
				delete(k.userSequenceMap, req.User)
				msg, _, remaining, err = k.glue.Provider().Spool().Get([]byte(req.User), false)
				if err != nil {
					k.log.Errorf("KaetzenDeaddrop failure: %s", err)
				}
				resp.Sequence = 1
				k.userSequenceMap[req.User] = resp.Sequence
			}
		}

		resp.Payload = string(msg)
		resp.QueueHint = remaining
	case userdb.ErrNoSuchUser, userdb.ErrNoIdentity:
		// Treat the user being missing as the user not having an
		// identity key to make enumeration attacks minutely harder.
		resp.StatusCode = deaddropStatusNoIdentity
	default:
	}
	if err != nil {
		k.log.Debugf("Failed to service request: %v (%v)", id, err)
	}

	return k.encodeResp(&resp), nil
}

func (k *kaetzchenDeaddrop) Halt() {
	// No termination required.
}

func (k *kaetzchenDeaddrop) encodeResp(resp *deaddropResponse) []byte {
	var out []byte
	enc := codec.NewEncoderBytes(&out, &k.jsonHandle)
	enc.Encode(resp)
	return out
}

// NewDeaddrop constructs a new Deaddrop Kaetzchen instance, providing the
// "deaddrop" capability on the configured endpoint.
func NewDeaddrop(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	k := &kaetzchenDeaddrop{
		log:    glue.LogBackend().GetLogger("kaetzchen/deaddrop"),
		glue:   glue,
		params: make(Parameters),
	}
	k.jsonHandle.Canonical = true
	k.jsonHandle.ErrorIfNoField = true
	k.params[ParameterEndpoint] = cfg.Endpoint
	k.userSequenceMap = make(map[string]int)

	return k, nil
}
