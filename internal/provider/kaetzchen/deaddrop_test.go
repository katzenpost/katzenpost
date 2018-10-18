// deaddrop_test.go - Tests for Deaddrop Kaetzchen.
// Copyright (C) 2018  David Stainton
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
	"testing"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/noise"
	"github.com/katzenpost/server/config"
	"github.com/stretchr/testify/require"
	"github.com/ugorji/go/codec"
)

func genDeaddropAuthToken(senderPrivateKey *ecdh.PrivateKey, recipientPublicKey *ecdh.PublicKey) (string, error) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	senderDH := noise.DHKey{
		Private: senderPrivateKey.Bytes(),
		Public:  senderPrivateKey.PublicKey().Bytes(),
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeK,
		Initiator:     true,
		StaticKeypair: senderDH,
		PeerStatic:    recipientPublicKey.Bytes(),
	})
	if err != nil {
		return "", err
	}
	plaintext := [0]byte{}
	ciphertext, _, _, err := hs.WriteMessage(nil, plaintext[:])
	encoded := base64.StdEncoding.EncodeToString([]byte(ciphertext))
	return encoded, err
}

func TestDeaddrop(t *testing.T) {
	require := require.New(t)

	cfg := &config.Kaetzchen{
		Capability: "deaddrop",
		Endpoint:   "endpoint",
		Config:     map[string]interface{}{},
		Disable:    false,
	}

	idKey, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err, "wtf")

	userKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")

	linkKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")

	mockProvider := &mockProvider{
		userName: "alice",
		userKey:  userKey.PublicKey(),
	}
	goo := &mockGlue{
		s: &mockServer{
			logBackend: logBackend,
			provider:   mockProvider,
			linkKey:    linkKey,
			cfg: &config.Config{
				Server:     &config.Server{},
				Logging:    &config.Logging{},
				Provider:   &config.Provider{},
				PKI:        &config.PKI{},
				Management: &config.Management{},
				Debug: &config.Debug{
					IdentityKey: idKey,
				},
			},
		},
	}
	deaddrop, err := NewDeaddrop(cfg, goo)
	require.NoError(err, "wtf")

	authToken, err := genDeaddropAuthToken(userKey, linkKey.PublicKey())
	require.NoError(err, "wtf")

	req := deaddropRequest{
		Version:   keyserverVersion,
		User:      "alice",
		AuthToken: authToken,
		Command:   "retrieve",
		Sequence:  0,
	}
	var out []byte
	jsonHandle := codec.JsonHandle{}
	jsonHandle.Canonical = true
	jsonHandle.ErrorIfNoField = true

	enc := codec.NewEncoderBytes(&out, &jsonHandle)
	err = enc.Encode(req)
	require.NoError(err, "wtf")

	id := uint64(0)
	response, err := deaddrop.OnRequest(id, out, true)
	require.NoError(err, "wtf")

	t.Logf("Deaddrop response is len %d", len(response))

	var resp deaddropResponse
	dec := codec.NewDecoderBytes(bytes.TrimRight(response, "\x00"), &jsonHandle)
	err = dec.Decode(&resp)
	require.NoError(err, "wtf")

	require.Equal(resp.StatusCode, deaddropStatusOk)
	require.Equal(resp.Version, deaddropVersion)
	require.Equal(resp.QueueHint, 1)
	require.Equal(resp.Sequence, req.Sequence+1)

	t.Logf("response payload len is %d", len(resp.Payload))

	// test authToken failure
	badAuthToken := make([]byte, len(authToken))
	copy(badAuthToken, authToken)
	badAuthToken[len(badAuthToken)-1] ^= 0x4 // flip a bit
	req.AuthToken = string(badAuthToken)
	enc = codec.NewEncoderBytes(&out, &jsonHandle)
	err = enc.Encode(req)
	require.NoError(err, "wtf")

	response, err = deaddrop.OnRequest(id, out, true)
	require.NoError(err)

	dec = codec.NewDecoderBytes(bytes.TrimRight(response, "\x00"), &jsonHandle)
	err = dec.Decode(&resp)
	require.NoError(err, "wtf")

	require.Equal(resp.StatusCode, deaddropStatusAuthError)
	require.Equal(resp.Version, deaddropVersion)
	require.Equal(resp.QueueHint, 0)
	require.Equal(resp.Sequence, 0)
}
