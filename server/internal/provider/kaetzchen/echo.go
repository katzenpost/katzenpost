// loop.go - Echo Kaetzchen.
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
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"gopkg.in/op/go-logging.v1"
)

// EchoCapability is the standardized capability for the echo service.
const EchoCapability = "echo"

type kaetzchenEcho struct {
	log *logging.Logger

	params Parameters
}

func (k *kaetzchenEcho) Capability() string {
	return EchoCapability
}

func (k *kaetzchenEcho) Parameters() Parameters {
	return k.params
}

func (k *kaetzchenEcho) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if !hasSURB {
		return nil, ErrNoResponse
	}

	k.log.Debugf("Handling request: %v", id)
	return payload, nil
}

func (k *kaetzchenEcho) Halt() {
	// No termination required.
}

// NewEcho constructs a new Echo Kaetzchen instance, providing the "echo"
// capability, on the configured endpoint.
func NewEcho(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	k := &kaetzchenEcho{
		log:    glue.LogBackend().GetLogger("kaetzchen/echo"),
		params: make(Parameters),
	}
	k.params[ParameterEndpoint] = cfg.Endpoint

	return k, nil
}
