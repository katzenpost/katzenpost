// kaetzchen.go - Katzenpost provider auto-responder agents.
// Copyright (C) 2018  Yawning Angel and David Stainton
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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/core/monotime"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/config"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/internal/packet"
	"golang.org/x/text/secure/precis"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
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
	deaddropCapability:  NewDeaddrop,
}

type KaetzchenWorker struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	ch        *channels.InfiniteChannel
	kaetzchen map[[sConstants.RecipientIDLength]byte]Kaetzchen

	dropCounter uint64
}

func (k *KaetzchenWorker) IsKaetzchen(recipient [sConstants.RecipientIDLength]byte) bool {
	_, ok := k.kaetzchen[recipient]
	return ok
}

func (k *KaetzchenWorker) registerKaetzchen(service Kaetzchen) error {
	capa := service.Capability()

	params := service.Parameters()
	if params == nil {
		return fmt.Errorf("provider: Kaetzchen: '%v' provided no parameters", capa)
	}

	// Sanitize the endpoint.
	var ep string
	if v, ok := params[ParameterEndpoint]; !ok {
		return fmt.Errorf("provider: Kaetzchen: '%v' provided no endpoint", capa)
	} else if ep, ok = v.(string); !ok {
		return fmt.Errorf("provider: Kaetzchen: '%v' invalid endpoint type: %T", capa, v)
	} else if epNorm, err := precis.UsernameCaseMapped.String(ep); err != nil {
		return fmt.Errorf("provider: Kaetzchen: '%v' invalid endpoint: %v", capa, err)
	} else if epNorm != ep {
		return fmt.Errorf("provider: Kaetzchen: '%v' invalid endpoint, not normalized", capa)
	}
	rawEp := []byte(ep)
	if len(rawEp) == 0 || len(rawEp) > sConstants.RecipientIDLength {
		return fmt.Errorf("provider: Kaetzchen: '%v' invalid endpoint, length out of bounds", capa)
	}

	// Register it in the map by endpoint.
	var epKey [sConstants.RecipientIDLength]byte
	copy(epKey[:], rawEp)
	if _, ok := k.kaetzchen[epKey]; ok {
		return fmt.Errorf("provider: Kaetzchen: '%v' endpoint '%v' already registered", capa, ep)
	}
	k.kaetzchen[epKey] = service
	k.log.Noticef("Registered Kaetzchen: '%v' -> '%v'.", ep, capa)

	return nil
}

func (k *KaetzchenWorker) OnKaetzchen(pkt *packet.Packet) {
	k.ch.In() <- pkt
}

func (k *KaetzchenWorker) getDropCounter() uint64 {
	return atomic.LoadUint64(&k.dropCounter)
}

func (k *KaetzchenWorker) incrementDropCounter() uint64 {
	return atomic.AddUint64(&k.dropCounter, uint64(1))
}

func (k *KaetzchenWorker) worker() {
	// Kaetzchen delay is our max dwell time.
	maxDwell := time.Duration(k.glue.Config().Debug.KaetzchenDelay) * time.Millisecond

	defer k.log.Debugf("Halting Kaetzchen internal worker.")

	ch := k.ch.Out()

	for {
		var pkt *packet.Packet
		select {
		case <-k.HaltCh():
			k.log.Debugf("Terminating gracefully.")
			return
		case e := <-ch:
			pkt = e.(*packet.Packet)
			if dwellTime := monotime.Now() - pkt.DispatchAt; dwellTime > maxDwell {
				count := k.incrementDropCounter()
				k.log.Debugf("Dropping packet: %v (Spend %v in queue), total drops %d", pkt.ID, dwellTime, count)
				pkt.Dispose()
				continue
			}
		}

		k.processKaetzchen(pkt)
	}
}

func (k *KaetzchenWorker) processKaetzchen(pkt *packet.Packet) {
	defer pkt.Dispose()

	ct, surb, err := packet.ParseForwardPacket(pkt)
	if err != nil {
		k.log.Debugf("Dropping Kaetzchen request: %v (%v)", pkt.ID, err)
		k.incrementDropCounter()
		return
	}

	var resp []byte
	dst, ok := k.kaetzchen[pkt.Recipient.ID]
	if ok {
		resp, err = dst.OnRequest(pkt.ID, ct, surb != nil)
	}
	switch {
	case err == nil:
	case err == ErrNoResponse:
		k.log.Debugf("Processed Kaetzchen request: %v (No response)", pkt.ID)
		return
	default:
		k.log.Debugf("Failed to handle Kaetzchen request: %v (%v)", pkt.ID, err)
		return
	}

	// Iff there is a SURB, generate a SURB-Reply and schedule.
	if surb != nil {
		// Prepend the response header.
		resp = append([]byte{0x01, 0x00}, resp...)

		respPkt, err := packet.NewPacketFromSURB(pkt, surb, resp)
		if err != nil {
			k.log.Debugf("Failed to generate SURB-Reply: %v (%v)", pkt.ID, err)
			return
		}

		k.log.Debugf("Handing off newly generated SURB-Reply: %v (Src:%v)", respPkt.ID, pkt.ID)
		k.glue.Scheduler().OnPacket(respPkt)
	} else if resp != nil {
		// This is silly and I'm not sure why anyone will do this, but
		// there's nothing that can be done at this point, the Kaetzchen
		// implementation should have caught this.
		k.log.Debugf("Kaetzchen message: %v (Has reply but no SURB)", pkt.ID)
	}
}

func (k *KaetzchenWorker) KaetzchenForPKI() map[string]map[string]interface{} {
	if len(k.kaetzchen) == 0 {
		return nil
	}

	m := make(map[string]map[string]interface{})
	for _, v := range k.kaetzchen {
		m[v.Capability()] = v.Parameters()
	}
	return m
}

func New(glue glue.Glue) (*KaetzchenWorker, error) {

	kaetzchenWorker := KaetzchenWorker{
		glue:      glue,
		log:       glue.LogBackend().GetLogger("kaetzchen_worker"),
		ch:        channels.NewInfiniteChannel(),
		kaetzchen: make(map[[sConstants.RecipientIDLength]byte]Kaetzchen),
	}

	// Initialize the internal Kaetzchen.
	capaMap := make(map[string]bool)
	for _, v := range glue.Config().Provider.Kaetzchen {
		capa := v.Capability
		if v.Disable {
			kaetzchenWorker.log.Noticef("Skipping disabled Kaetzchen: '%v'.", capa)
			continue
		}

		ctor, ok := BuiltInCtors[capa]
		if !ok {
			return nil, fmt.Errorf("provider: Kaetzchen: Unsupported capability: '%v'", capa)
		}

		k, err := ctor(v, glue)
		if err != nil {
			return nil, err
		}
		if err = kaetzchenWorker.registerKaetzchen(k); err != nil {
			return nil, err
		}

		if capaMap[capa] {
			return nil, fmt.Errorf("provider: Kaetzchen '%v' registered more than once", capa)
		}
		capaMap[capa] = true
	}

	// Start the workers.
	for i := 0; i < glue.Config().Debug.NumKaetzchenWorkers; i++ {
		kaetzchenWorker.log.Noticef("Starting Kaetzchen worker: %d", i)
		kaetzchenWorker.Go(kaetzchenWorker.worker)
	}

	return &kaetzchenWorker, nil
}
