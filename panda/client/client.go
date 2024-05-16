// client.go - mixnet PANDA client
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

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/charmbracelet/log"
	"github.com/ugorji/go/codec"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/panda/common"
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	ShutdownError     = Error("panda: shutdown requested")
	SyntaxError       = Error("panda failure, syntax error")
	TagContendedError = Error("panda failure, tag contended error")
	StorageError      = Error("panda failure, storage error")
)

// Panda is a PANDA client that uses our mixnet client library
// to communicate with the PANDA kaetzchen service.
type Panda struct {
	session    *thin.ThinClient
	log        *log.Logger
	blobSize   int
	jsonHandle codec.JsonHandle
	recipient  []byte
	provider   string
}

// Padding returns the size of the ciphertext blobs
// to be exchanged.
func (p *Panda) Padding() int {
	return p.blobSize
}

// Exchange performs a PANDA protocol message exchange
func (p *Panda) Exchange(id, message []byte, shutdown <-chan interface{}) ([]byte, error) {
	delay := 1 * time.Second
	for {
		request := common.PandaRequest{
			Version: common.PandaVersion,
			Tag:     hex.EncodeToString(id),
			Message: base64.StdEncoding.EncodeToString(message),
		}
		var rawRequest []byte
		var dec *codec.Decoder
		response := &common.PandaResponse{}
		enc := codec.NewEncoderBytes(&rawRequest, &p.jsonHandle)
		enc.Encode(request)
		p.log.Debugf("PANDA exchange sending kaetzchen query to %s@%s", p.recipient, p.provider)
		mesgID := p.session.NewMessageID()
		doc := p.session.PKIDocument()
		providerKey, err := doc.GetServiceNode(p.provider)
		if err != nil {
			return nil, err
		}
		id := hash.Sum256(providerKey.IdentityKey)
		reply, err := p.session.BlockingSendReliableMessage(mesgID, rawRequest, &id, p.recipient)
		if err != nil {
			// do not spin on error and retry connection
			goto Sleep
		}
		dec = codec.NewDecoderBytes(bytes.TrimRight(reply, "\x00"), &p.jsonHandle)
		if err := dec.Decode(response); err != nil {
			p.log.Debugf("Failed to decode PANDA response: (%v)", err)
			return nil, fmt.Errorf("Failed to decode PANDA response: (%v)", err)
		}
		if response.Version != common.PandaVersion {
			p.log.Warn("warning, PANDA server version mismatch")
		}
		switch response.StatusCode {
		case common.PandaStatusReceived1:
			if len(response.Message) == 0 {
				goto Sleep
			}
			decoded, err := base64.StdEncoding.DecodeString(response.Message)
			if err != nil {
				return nil, err
			}
			return decoded, nil
		case common.PandaStatusReceived2:
			if len(response.Message) == 0 {
				goto Sleep
			}
			decoded, err := base64.StdEncoding.DecodeString(response.Message)
			if err != nil {
				return nil, err
			}
			return decoded, nil
		case common.PandaStatusSyntaxError:
			return nil, SyntaxError
		case common.PandaStatusTagContendedError:
			return nil, TagContendedError
		case common.PandaStatusRequestRecordedError:
			goto Sleep
		case common.PandaStatusStorageError:
			return nil, StorageError
		}
	Sleep:
		select {
		case <-shutdown:
			return nil, ShutdownError
		case <-time.After(delay):
			delay *= 2
			if delay > time.Hour {
				delay = time.Hour
			}
		}
	}

	panic("unreachable")
}

// New creates a new Panda instance.
func New(blobSize int, s *thin.ThinClient, log *log.Logger, recipient []byte, provider string) *Panda {
	p := &Panda{
		session:   s,
		blobSize:  blobSize,
		log:       log,
		recipient: recipient,
		provider:  provider,
	}
	p.jsonHandle.Canonical = true
	p.jsonHandle.ErrorIfNoField = true
	return p
}
