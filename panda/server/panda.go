// panda.go - PANDA Kaetzchen.
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

package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"time"

	"github.com/katzenpost/katzenpost/panda/common"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

// PANDA - Phrase Automated Nym Discovery Authentication
//
// This Kaetzchen service was inspired by AGL's appengine Panda server:
// https://github.com/agl/pond/blob/master/panda/appengine-server/panda/main.go

// ErrNoSURBRequest is the error returned when no SURB accompanies a query.
var ErrNoSURBRequest = errors.New("Request received without SURB")

// Panda is the PANDA server type.
type Panda struct {
	log *logging.Logger

	jsonHandle codec.JsonHandle
	store      *PandaStorage
	expiration time.Duration
}

// OnRequest services a client request and returns the reply.
func (k *Panda) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if !hasSURB {
		k.log.Debugf("Received request %d without a SURB", id)
		return nil, ErrNoSURBRequest
	}
	k.log.Debugf("Handling request %d", id)
	resp := common.PandaResponse{
		Version:    common.PandaVersion,
		StatusCode: common.PandaStatusSyntaxError,
	}

	// Parse out the request payload.
	var req common.PandaRequest
	dec := codec.NewDecoderBytes(bytes.TrimRight(payload, "\x00"), &k.jsonHandle)
	if err := dec.Decode(&req); err != nil {
		k.log.Debugf("failed to decode request: (%v)", err)
		return k.encodeResp(&resp), nil
	}
	if req.Version != common.PandaVersion {
		k.log.Debugf("failed to parse request: (invalid version: %v)", req.Version)
		return k.encodeResp(&resp), nil
	}
	if len(req.Message) == 0 {
		k.log.Debugf("message size is zero")
		return k.encodeResp(&resp), nil
	}
	tag, newPosting, err := postingFromRequest(&req)
	if err != nil {
		k.log.Debug("cannot decode tag and message")
		return k.encodeResp(&resp), nil
	}

	storedPosting, err := k.store.Get(tag)
	if storedPosting != nil {
		storedPosting.Lock()
		defer storedPosting.Unlock()
	}
	if err == common.ErrNoSuchPandaTag || err == nil && storedPosting.Expired(k.expiration) {
		err = k.store.Put(tag, newPosting)
		if err != nil {
			return nil, err
		}
		resp.StatusCode = common.PandaStatusReceived1
		return k.encodeResp(&resp), nil
	}
	if err != nil {
		resp.StatusCode = common.PandaStatusStorageError
		k.log.Debugf("PANDA storage error: %s", err)
		return k.encodeResp(&resp), nil
	}
	if len(storedPosting.B) > 0 {
		if bytes.Equal(storedPosting.A, newPosting.A) {
			resp.Message = base64.StdEncoding.EncodeToString(storedPosting.B)
			resp.StatusCode = common.PandaStatusReceived2
			return k.encodeResp(&resp), nil
		} else if bytes.Equal(storedPosting.B, newPosting.A) {
			resp.Message = base64.StdEncoding.EncodeToString(storedPosting.A)
			resp.StatusCode = common.PandaStatusReceived2
			return k.encodeResp(&resp), nil
		} else {
			resp.StatusCode = common.PandaStatusTagContendedError
			return k.encodeResp(&resp), nil
		}
		// not reached
	}
	if bytes.Equal(storedPosting.A, newPosting.A) {
		resp.StatusCode = common.PandaStatusRequestRecordedError
		return k.encodeResp(&resp), nil
	}
	storedPosting.B = newPosting.A
	err = k.store.Replace(tag, storedPosting)
	if err != nil {
		resp.StatusCode = common.PandaStatusStorageError
		return k.encodeResp(&resp), nil
	}

	resp.Message = base64.StdEncoding.EncodeToString(storedPosting.A)
	resp.StatusCode = common.PandaStatusReceived2
	return k.encodeResp(&resp), nil
}

func (k *Panda) encodeResp(resp *common.PandaResponse) []byte {
	var out []byte
	enc := codec.NewEncoderBytes(&out, &k.jsonHandle)
	if err := enc.Encode(resp); err != nil {
		panic(err)
	}
	return out
}

// New constructs a new Panda server instance
func New(log *logging.Logger, fileStore string, dwellDuration time.Duration, writeBackInterval time.Duration) (*Panda, error) {
	store, err := NewPandaStorage(fileStore, dwellDuration, writeBackInterval)
	if err != nil {
		return nil, err
	}
	k := &Panda{
		log:        log,
		store:      store,
		expiration: dwellDuration,
	}
	k.jsonHandle.Canonical = true
	k.jsonHandle.ErrorIfNoField = true
	return k, nil
}
