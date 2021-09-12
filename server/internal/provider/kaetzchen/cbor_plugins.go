// cbor_plugins2.go - cbor plugin system for kaetzchen services
// Copyright (C) 2021  David Stainton.
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
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/text/secure/precis"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/monotime"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

// PluginChans maps from Recipient ID to channel.
type PluginChans = map[[constants.RecipientIDLength]byte]*channels.InfiniteChannel

// PluginName is the name of a plugin.
type PluginName = string

// PluginParameters maps from parameter key to value.
type PluginParameters = map[PluginName]interface{}

// ServiceMap maps from plugin name to plugin parameters
// and is used by Mix Descriptors which describe Providers
// with plugins. Each plugin can optionally set one or more
// parameters.
type ServiceMap = map[PluginName]PluginParameters

// Request is the struct type used in service query requests to plugins.
type Request struct {
	ID      uint64
	Payload []byte
	HasSURB bool
}

func (r *Request) Marshal() ([]byte, error) {
	return cbor.Marshal(r)
}

func (r *Request) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, r)
}

type requestFactory struct{}

func (p *requestFactory) Build() cborplugin.Command {
	return new(Request)
}

// Response is the response received after sending a Request to the plugin.
type Response struct {
	Payload []byte
}

func (r *Response) Marshal() ([]byte, error) {
	return cbor.Marshal(r)
}

func (r *Response) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, r)
}

// CBORPluginWorker is similar to Kaetzchen worker but uses
// CBOR over UNIX domain socket to talk to plugins.
type CBORPluginWorker struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	haltOnce    sync.Once
	pluginChans PluginChans
	clients     []*cborplugin.Client
}

// OnKaetzchen enqueues the pkt for processing by our thread pool of plugins.
func (k *CBORPluginWorker) OnKaetzchen(pkt *packet.Packet) {
	handlerCh, ok := k.pluginChans[pkt.Recipient.ID]
	if !ok {
		k.log.Debugf("Failed to find handler. Dropping Kaetzchen request: %v", pkt.ID)
		return
	}
	handlerCh.In() <- pkt
}

func (k *CBORPluginWorker) worker(recipient [constants.RecipientIDLength]byte, pluginClient *cborplugin.Client) {

	// Kaetzchen delay is our max dwell time.
	maxDwell := time.Duration(k.glue.Config().Debug.KaetzchenDelay) * time.Millisecond

	defer k.haltOnce.Do(k.haltAllClients)

	handlerCh, ok := k.pluginChans[recipient]
	if !ok {
		k.log.Debugf("Failed to find handler. Dropping Kaetzchen request: %v", recipient)
		kaetzchenRequestsDropped.Inc()
		return
	}
	ch := handlerCh.Out()

	for {
		var pkt *packet.Packet
		select {
		case <-k.HaltCh():
			k.log.Debugf("Terminating gracefully.")
			return
		case e := <-ch:
			pkt = e.(*packet.Packet)
			if dwellTime := monotime.Now() - pkt.DispatchAt; dwellTime > maxDwell {
				k.log.Debugf("Dropping packet: %v (Spend %v in queue)", pkt.ID, dwellTime)
				packetsDropped.Inc()
				pkt.Dispose()
				continue
			}
		}

		k.processKaetzchen(pkt, pluginClient)
		kaetzchenRequests.Inc()
	}
}

func (k *CBORPluginWorker) haltAllClients() {
	k.log.Debug("Halting plugin clients.")
	for _, client := range k.clients {
		go client.Halt()
	}
}

func (k *CBORPluginWorker) processKaetzchen(pkt *packet.Packet, pluginClient *cborplugin.Client) {
	kaetzchenRequestsTimer = prometheus.NewTimer(kaetzchenRequestsDuration)
	defer kaetzchenRequestsTimer.ObserveDuration()
	defer pkt.Dispose()

	ct, surb, err := packet.ParseForwardPacket(pkt)
	if err != nil {
		k.log.Debugf("Dropping Kaetzchen request: %v (%v)", pkt.ID, err)
		kaetzchenRequestsDropped.Inc()
		return
	}
	ctLen := binary.BigEndian.Uint32(ct[:4])
	if ctLen+4 > uint32(len(ct)) {
		k.log.Error("length prefixing is incorrect in cbor plugin query")
		kaetzchenRequestsDropped.Inc()
		return
	}

	pluginClient.WriteChan() <- &Request{
		ID:      pkt.ID,
		Payload: ct[4 : 4+ctLen],
		HasSURB: surb != nil,
	}

	rawResponse := <-pluginClient.ReadChan()
	resp, err := rawResponse.Marshal()
	switch err {
	case nil:
	case ErrNoResponse:
		k.log.Debugf("Processed Kaetzchen request: %v (No response)", pkt.ID)
		kaetzchenRequests.Inc()
		return
	default:
		k.log.Debugf("Failed to handle Kaetzchen request: %v (%v), response: %s", pkt.ID, err, resp)
		return
	}

	// Iff there is a SURB, generate a SURB-Reply and schedule.
	if surb != nil {
		// Length prefix encode payload.
		payload := make([]byte, 4+len(resp))
		binary.BigEndian.PutUint32(payload[:4], uint32(len(resp)))
		copy(payload[4:], resp)

		// Prepend the response header.
		payload = append([]byte{0x01, 0x00}, payload...)

		respPkt, err := packet.NewPacketFromSURB(pkt, surb, payload)
		if err != nil {
			k.log.Debugf("Failed to generate SURB-Reply: %v (%v)", pkt.ID, err)
			return
		}

		k.log.Debugf("Handing off newly generated SURB-Reply: %v (Src:%v)", respPkt.ID, pkt.ID)
		k.glue.Scheduler().OnPacket(respPkt)
		return
	}
	k.log.Debugf("No SURB provided: %v", pkt.ID)
}

// KaetzchenForPKI returns the plugins Parameters map for publication in the PKI doc.
func (k *CBORPluginWorker) KaetzchenForPKI() ServiceMap {
	s := make(ServiceMap)
	for _, k := range k.clients {
		capa := k.Capability()
		if _, ok := s[capa]; ok {
			// skip adding twice
			continue
		}
		params := make(PluginParameters)
		p := k.GetParameters()
		if p != nil {
			for key, value := range *p {
				params[key] = value
			}
		}
		s[capa] = params
	}
	return s
}

// IsKaetzchen returns true if the given recipient is one of our workers.
func (k *CBORPluginWorker) IsKaetzchen(recipient [constants.RecipientIDLength]byte) bool {
	_, ok := k.pluginChans[recipient]
	return ok
}

func (k *CBORPluginWorker) launch(command, capability, endpoint string, args []string) (*cborplugin.Client, error) {
	k.log.Debugf("Launching plugin: %s", command)
	plugin := cborplugin.NewClient(k.glue.LogBackend(), capability, endpoint, &requestFactory{})
	err := plugin.Start(command, args)
	return plugin, err
}

// NewCBORPluginWorker returns a new CBORPluginWorker
func NewCBORPluginWorker(glue glue.Glue) (*CBORPluginWorker, error) {

	kaetzchenWorker := CBORPluginWorker{
		glue:        glue,
		log:         glue.LogBackend().GetLogger("CBOR plugin worker"),
		pluginChans: make(PluginChans),
		clients:     make([]*cborplugin.Client, 0),
	}

	capaMap := make(map[string]bool)

	for _, pluginConf := range glue.Config().Provider.CBORPluginKaetzchen {
		kaetzchenWorker.log.Noticef("Configuring plugin handler for %s", pluginConf.Capability)

		// Ensure no duplicates.
		capa := pluginConf.Capability
		if capa == "" {
			return nil, errors.New("kaetzchen plugin capability cannot be empty string")
		}
		if pluginConf.Disable {
			kaetzchenWorker.log.Noticef("Skipping disabled Kaetzchen: '%v'.", capa)
			continue
		}
		if capaMap[capa] {
			return nil, fmt.Errorf("provider: Kaetzchen '%v' registered more than once", capa)
		}

		// Sanitize the endpoint.
		if pluginConf.Endpoint == "" {
			return nil, fmt.Errorf("provider: Kaetzchen: '%v' provided no endpoint", capa)
		} else if epNorm, err := precis.UsernameCaseMapped.String(pluginConf.Endpoint); err != nil {
			return nil, fmt.Errorf("provider: Kaetzchen: '%v' invalid endpoint: %v", capa, err)
		} else if epNorm != pluginConf.Endpoint {
			return nil, fmt.Errorf("provider: Kaetzchen: '%v' invalid endpoint, not normalized", capa)
		}
		rawEp := []byte(pluginConf.Endpoint)
		if len(rawEp) == 0 || len(rawEp) > constants.RecipientIDLength {
			return nil, fmt.Errorf("provider: Kaetzchen: '%v' invalid endpoint, length out of bounds", capa)
		}

		// Add an infinite channel for this plugin.
		var endpoint [constants.RecipientIDLength]byte
		copy(endpoint[:], rawEp)
		kaetzchenWorker.pluginChans[endpoint] = channels.NewInfiniteChannel()
		kaetzchenWorker.log.Noticef("Starting Kaetzchen plugin client: %s", capa)

		var args []string
		if len(pluginConf.Config) > 0 {
			args = []string{}
			for key, val := range pluginConf.Config {
				args = append(args, fmt.Sprintf("-%s", key), val.(string))
			}
		}

		pluginClient, err := kaetzchenWorker.launch(pluginConf.Command, pluginConf.Capability, pluginConf.Endpoint, args)
		if err != nil {
			kaetzchenWorker.log.Error("Failed to start a plugin client: %s", err)
			return nil, err
		}

		// Accumulate a list of all clients to facilitate clean shutdown.
		kaetzchenWorker.clients = append(kaetzchenWorker.clients, pluginClient)

		// Start the workers _after_ we have added all of the entries to pluginChans
		// otherwise the worker() goroutines race this thread.
		defer kaetzchenWorker.Go(func() {
			kaetzchenWorker.worker(endpoint, pluginClient)
		})

		capaMap[capa] = true
	}

	return &kaetzchenWorker, nil
}
