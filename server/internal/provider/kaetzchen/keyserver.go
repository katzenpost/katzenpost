// keyserver.go - Keyserver Kaetzchen.
// Copyright (C) 2018  Yawning Angel.
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

	"github.com/katzenpost/server/config"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/userdb"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

const (
	keyserverCapability = "keyserver"
	keyserverVersion    = 0

	keyserverStatusOk          = 0
	keyserverStatusSyntaxError = 1
	keyserverStatusNoIdentity  = 2
)

type keyserverRequest struct {
	Version int
	User    string
}

type keyserverResponse struct {
	Version    int
	StatusCode int
	User       string
	PublicKey  string
}

type kaetzchenKeyserver struct {
	log  *logging.Logger
	glue glue.Glue

	params     Parameters
	jsonHandle codec.JsonHandle
}

func (k *kaetzchenKeyserver) Capability() string {
	return keyserverCapability
}

func (k *kaetzchenKeyserver) Parameters() Parameters {
	return k.params
}

func (k *kaetzchenKeyserver) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if !hasSURB {
		return nil, ErrNoResponse
	}

	k.log.Debugf("Handling request: %v", id)
	resp := keyserverResponse{
		Version:    keyserverVersion,
		StatusCode: keyserverStatusSyntaxError,
	}

	// Parse out the request payload.
	var req keyserverRequest
	dec := codec.NewDecoderBytes(bytes.TrimRight(payload, "\x00"), &k.jsonHandle)
	if err := dec.Decode(&req); err != nil {
		k.log.Debugf("Failed to decode request: %v (%v)", id, err)
		return k.encodeResp(&resp), nil
	}
	if req.Version != keyserverVersion {
		k.log.Debugf("Failed to parse request: %v (invalid version: %v)", id, req.Version)
		return k.encodeResp(&resp), nil
	}
	resp.User = req.User

	// Query the public key.
	pubKey, err := k.glue.Provider().UserDB().Identity([]byte(req.User))
	switch err {
	case nil:
		resp.StatusCode = keyserverStatusOk
		resp.PublicKey = pubKey.String()
	case userdb.ErrNoSuchUser, userdb.ErrNoIdentity:
		// Treat the user being missing as the user not having an
		// identity key to make enumeration attacks minutely harder.
		resp.StatusCode = keyserverStatusNoIdentity
	default:
		resp.StatusCode = keyserverStatusSyntaxError
	}
	if err != nil {
		k.log.Debugf("Failed to service request: %v (%v)", id, err)
	}

	return k.encodeResp(&resp), nil
}

func (k *kaetzchenKeyserver) Halt() {
	// No termination required.
}

func (k *kaetzchenKeyserver) encodeResp(resp *keyserverResponse) []byte {
	var out []byte
	enc := codec.NewEncoderBytes(&out, &k.jsonHandle)
	enc.Encode(resp)
	return out
}

// NewKeyserver constructs a new Keyserver Kaetzchen instance, providing the
// "keyserver" capability on the configured endpoint.
func NewKeyserver(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	k := &kaetzchenKeyserver{
		log:    glue.LogBackend().GetLogger("kaetzchen/keyserver"),
		glue:   glue,
		params: make(Parameters),
	}
	k.jsonHandle.Canonical = true
	k.jsonHandle.ErrorIfNoField = true
	k.params[ParameterEndpoint] = cfg.Endpoint

	return k, nil
}
