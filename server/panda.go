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

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/panda/common"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

// PANDA - Phrase Automated Nym Discovery Authentication
//
// This Kaetzchen service was inspired by AGL's appengine Panda server:
// https://github.com/agl/pond/blob/master/panda/appengine-server/panda/main.go

// PandaPosting is the data structure stored on Panda
// server with each client interaction.
type PandaPosting struct {
	Dirty    bool
	UnixTime int64
	A, B     []byte
}

// Expired returns true if the posting is
// older than the specified expiration duration.
func (p *PandaPosting) Expired(expiration time.Duration) bool {
	postingTime := time.Unix(p.UnixTime, 0)
	return time.Now().After(postingTime.Add(expiration))
}

func postingFromRequest(req *common.PandaRequest) (*[common.PandaTagLength]byte, *PandaPosting, error) {
	tagRaw, err := hex.DecodeString(req.Tag)
	if err != nil {
		return nil, nil, err
	}
	if len(tagRaw) != common.PandaTagLength {
		return nil, nil, errors.New("postingFromRequest failure: tag not 32 bytes in length")
	}
	message, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		return nil, nil, err
	}
	p := &PandaPosting{
		UnixTime: time.Now().Unix(),
		A:        message,
		B:        nil,
	}
	tag := [common.PandaTagLength]byte{}
	copy(tag[:], tagRaw)
	return &tag, p, nil
}

// PandaPostStorage is the interface provided by all PANDA server
// storage implementations.
type PandaPostStorage interface {

	// Put stores a posting in the data store
	// such that it is referenced by the given tag.
	Put(tag *[common.PandaTagLength]byte, posting *PandaPosting) error

	// Get returns a posting from the data store
	// that is referenced by the given tag.
	Get(tag *[common.PandaTagLength]byte) (*PandaPosting, error)

	// Replace replaces the stored posting.
	Replace(tag *[common.PandaTagLength]byte, posting *PandaPosting) error

	// Vacuum removes the postings that have expired.
	Vacuum(expiration time.Duration) error
}

// ErrNoSURBRequest is the error returned when no SURB accompanies a query.
var ErrNoSURBRequest = errors.New("Request received without SURB")

// Panda is the PANDA server type.
type Panda struct {
	log *logging.Logger

	jsonHandle codec.JsonHandle
	store      PandaPostStorage
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
		k.log.Debugf("cannot decode tag and message")
		return k.encodeResp(&resp), nil
	}

	storedPosting, err := k.store.Get(tag)
	if err == common.ErrNoSuchPandaTag || err == nil && storedPosting.Expired(k.expiration) {
		k.store.Put(tag, newPosting)
		resp.StatusCode = common.PandaStatusReceived1
		k.maybeGarbageCollect()
		return k.encodeResp(&resp), nil
	}
	if err != nil {
		resp.StatusCode = common.PandaStatusStorageError
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
	enc.Encode(resp)
	return out
}

func (k *Panda) maybeGarbageCollect() {
	var randByte [1]byte
	_, err := io.ReadFull(rand.Reader, randByte[:])
	if err != nil {
		k.log.Error("wtf, cannot read from rand.Reader")
		return
	}
	if randByte[0] >= 2 {
		return
	}
	// Every one in 128 insertions we'll clean out expired postings.
	err = k.store.Vacuum(k.expiration)
	if err != nil {
		k.log.Errorf("storage Vacuum failed: %s", err)
	}
}

// New constructs a new Panda server instance
func New(dwellTime time.Duration, log *logging.Logger, fileStore PandaPostStorage) *Panda {
	k := &Panda{
		log:        log,
		store:      fileStore,
		expiration: dwellTime,
	}
	k.jsonHandle.Canonical = true
	k.jsonHandle.ErrorIfNoField = true
	return k
}
