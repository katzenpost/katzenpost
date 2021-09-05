// loop.go - Loop Kaetzchen.
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
	"github.com/katzenpost/server/config"
	"github.com/katzenpost/server/internal/glue"
	"gopkg.in/op/go-logging.v1"
)

// LoopCapability is the standardized capability for the loop/discard service.
const LoopCapability = "loop"

type kaetzchenLoop struct {
	log *logging.Logger

	params Parameters
}

func (k *kaetzchenLoop) Capability() string {
	return LoopCapability
}

func (k *kaetzchenLoop) Parameters() Parameters {
	return k.params
}

func (k *kaetzchenLoop) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if !hasSURB {
		return nil, ErrNoResponse
	}

	k.log.Debugf("Handling request: %v", id)

	// TODO: Should this do anything with the payload, and should this send
	// a meaningful response?  Maybe a digest of the payload?

	return nil, nil
}

func (k *kaetzchenLoop) Halt() {
	// No termination required.
}

// NewLoop constructs a new Loop Kaetzchen instance, providing the "loop"
// capability, on the configured endpoint.
func NewLoop(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	k := &kaetzchenLoop{
		log:    glue.LogBackend().GetLogger("kaetzchen/loop"),
		params: make(Parameters),
	}
	k.params[ParameterEndpoint] = cfg.Endpoint

	return k, nil
}
