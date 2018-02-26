// kaetzchen.go - Katzenpost provider auto-responder agents.
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

// Package kaetzchen implements support for provider side auto-responder
// agents.
package kaetzchen

import (
	"errors"

	"github.com/katzenpost/server/config"
	"github.com/katzenpost/server/internal/glue"
)

// ParameterEndpoint is the mandatory Parameter key indicationg the
// Kaetzchen's endpoint.
const ParameterEndpoint = "endpoint"

// ErrNoResponse is the error returned from OnMessage() when there is no
// response to be sent (rather than an empty response).
var ErrNoResponse = errors.New("kaetzchen: message has no response")

// Parameters is the map describing each Kaetzchen's parameters to
// be published in the Provider's descriptor.
type Parameters map[string]interface{}

// Kaetzchen is the interface implemented by each auto-responder agent.
type Kaetzchen interface {
	// Capability returns the agent's functionality for publication in
	// the Provider's descriptor.
	Capability() string

	// Parameters returns the agent's paramenters for publication in
	// the Provider's descriptor.
	Parameters() Parameters

	// OnRequest is the method that is called when the Provider receives
	// a request desgined for a particular agent.  The caller will handle
	// extracting the payload component of the message.
	//
	// Implementations MUST:
	//
	//  * Be thread (go routine) safe.
	//
	//  * Return ErrNoResponse if there is no response to be sent.  A nil
	//    byte slice and nil error will result in a response with a 0 byte
	//    payload being sent.
	//
	//  * NOT assume payload will be valid past the call to OnMessage.
	//    Any contents that need to be preserved, MUST be copied out,
	//    except if it is only used as a part of the response body.
	//
	//  * Return relatively quickly.  Kaetzchen are executed in the provider
	//    worker context, and excessive processing time will adversely impact
	//    provider performance.
	OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error)

	// Halt cleans up the agent prior to de-registration and teardown.
	Halt()
}

// BuiltInCtorFn is the constructor type for a built-in Kaetzchen.
type BuiltInCtorFn func(*config.Kaetzchen, glue.Glue) (Kaetzchen, error)

// BuiltInCtors are the constructors for all built-in Kaetzchen.
var BuiltInCtors = map[string]BuiltInCtorFn{
	LoopCapability:      NewLoop,
	keyserverCapability: NewKeyserver,
}
