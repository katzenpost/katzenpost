// cbor_plugins.go - cbor plugin system for kaetzchen services
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
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/text/secure/precis"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

const InboundPacketsChannelSize = 1000

// PluginChans maps from Recipient ID to channel.
type PluginChans = map[[constants.RecipientIDLength]byte]chan interface{}

// PluginName is the name of a plugin.
type PluginName = string

// PluginParameters maps from parameter key to value.
type PluginParameters = map[PluginName]interface{}

// ServiceMap maps from plugin name to plugin parameters
// and is used by Mix Descriptors which describe Providers
// with plugins. Each plugin can optionally set one or more
// parameters.
type ServiceMap = map[PluginName]PluginParameters

// CBORPluginWorker is similar to Kaetzchen worker but uses
// CBOR over UNIX domain socket to talk to plugins.
type CBORPluginWorker struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger
	geo  *geo.Geometry

	haltOnce    sync.Once
	pluginChans PluginChans
	clients     []*cborplugin.Client
}

// OnKaetzchen enqueues the pkt for processing by our thread pool of plugins.
func (k *CBORPluginWorker) OnKaetzchen(pkt *packet.Packet) {
	k.Lock()
	handlerCh, ok := k.pluginChans[pkt.Recipient.ID]
	k.Unlock()
	if !ok {
		k.log.Debugf("Failed to find handler. Dropping Kaetzchen request: %v", pkt.ID)
		return
	}
	handlerCh <- pkt
}

func (k *CBORPluginWorker) worker(recipient [constants.RecipientIDLength]byte, pluginClient *cborplugin.Client) {
	// Kaetzchen delay is our max dwell time.
	maxDwell := time.Duration(k.glue.Config().Debug.KaetzchenDelay) * time.Millisecond

	defer k.haltOnce.Do(k.haltAllClients)

	k.Lock()
	handlerCh, ok := k.pluginChans[recipient]
	k.Unlock()
	if !ok {
		k.log.Debugf("Failed to find handler. Dropping Kaetzchen request: %v", recipient)
		instrument.KaetzchenRequestsDropped(1)
		return
	}
	ch := handlerCh

	for {
		var pkt *packet.Packet
		select {
		case <-k.HaltCh():
			k.log.Debugf("Terminating gracefully.")
			return
		case e := <-ch:
			pkt = e.(*packet.Packet)
			if dwellTime := time.Now().Sub(pkt.DispatchAt); dwellTime > maxDwell {
				k.log.Debugf("Dropping packet: %v (Spend %v in queue)", pkt.ID, dwellTime)
				instrument.PacketsDropped()
				pkt.Dispose()
				continue
			}
		}

		k.processKaetzchen(pkt, pluginClient)
		instrument.KaetzchenRequests()
	}
}

func (k *CBORPluginWorker) haltAllClients() {
	k.log.Debug("Halting plugin clients.")
	for _, client := range k.clients {
		go client.Halt()
	}
}

func (k *CBORPluginWorker) processKaetzchen(pkt *packet.Packet, pluginClient *cborplugin.Client) {
	defer pkt.Dispose()
	pluginCap := pluginClient.Capability()
	payload, surb, err := packet.ParseForwardPacket(pkt)
	if err != nil {
		k.log.Debugf("%v: Dropping Kaetzchen request: %v (%v)", pluginCap, pkt.ID, err)
		instrument.KaetzchenRequestsDropped(1)
		return
	}

	pluginClient.WriteChan() <- &cborplugin.Request{
		ID:        pkt.ID,
		RequestAt: time.Now(),
		Delay:     pkt.Delay,
		Payload:   payload,
		SURB:      surb,
	}
}

func (k *CBORPluginWorker) sendworker(pluginClient *cborplugin.Client) {
	pluginCap := pluginClient.Capability()
	surbLength := k.geo.SURBLength
	for {
		select {
		case <-k.HaltCh():
			return
		case cborResponse := <-pluginClient.ReadChan():
			switch r := cborResponse.(type) {
			case *cborplugin.Response:
				if len(r.Payload) > k.geo.UserForwardPayloadLength {
					// response is probably invalid, so drop it
					k.log.Errorf("%v: Got response too long: %d > max (%d)",
						pluginCap, len(r.Payload), k.geo.UserForwardPayloadLength)
					instrument.KaetzchenRequestsDropped(1)
					continue
				}
				// Iff there is a SURB, generate a SURB-Reply and schedule.
				if len(r.SURB) == surbLength {
					respPkt, err := packet.NewPacketFromSURB(r.SURB, r.Payload, k.geo)
					if err != nil {
						k.log.Debugf("%v: Failed to generate SURB-Reply: %v (%v)", pluginCap, r.ID, err)
						continue
					}
					// Set the packet queue delay
					delay := r.Delay - time.Since(r.RequestAt)
					if delay < 0 {
						respPkt.Delay = 0
					} else {
						respPkt.Delay = delay
					}

					k.log.Debugf("%v: Handing off newly generated SURB-Reply: %v (Src:%v)", pluginCap, respPkt.ID, r.ID)
					k.glue.Scheduler().OnPacket(respPkt)
				} else {
					k.log.Debugf("No SURB provided: %v", r.ID)
				}
			default:
				// received some unknown command type
				k.log.Errorf("%v: Failed to handle Kaetzchen request, unknown command type: (%v), response: %s", pluginCap, r, cborResponse)
				instrument.KaetzchenRequestsDropped(1)
			}
		}
	}
}

// KaetzchenForPKI returns the plugins Parameters map for publication in the PKI doc.
func (k *CBORPluginWorker) KaetzchenForPKI() ServiceMap {
	s := make(ServiceMap)
	k.Lock()
	defer k.Unlock()
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
	k.Lock()
	defer k.Unlock()
	return k.isKaetzchen(recipient)
}

// isKaetzchen returns true if the given recipient is one of our workers.
func (k *CBORPluginWorker) isKaetzchen(recipient [constants.RecipientIDLength]byte) bool {
	_, ok := k.pluginChans[recipient]
	return ok
}

func (k *CBORPluginWorker) launch(command, capability, endpoint string, args []string) (*cborplugin.Client, error) {
	k.log.Debugf("Launching plugin: %s", command)
	plugin := cborplugin.NewClient(k.glue.LogBackend(), capability, endpoint, &cborplugin.ResponseMessageFactory{})
	err := plugin.Start(command, args)
	return plugin, err
}

func (k *CBORPluginWorker) unregister(endpoint [constants.RecipientIDLength]byte, pluginClient *cborplugin.Client) {
	k.log.Debugf("Unregistering %s", pluginClient.Capability())
	k.Lock()
	defer k.Unlock()
	delete(k.pluginChans, endpoint)
	for i, c := range k.clients {
		if c == pluginClient {
			// last element in clients
			if len(k.clients) == i+1 {
				k.clients = k.clients[:i]
			} else {
				k.clients = append(k.clients[:i], k.clients[i+1:]...)
			}
			k.log.Debugf("Unregistered %s", pluginClient.Capability())
			break
		}
	}
}

// NewCBORPluginWorker returns a new CBORPluginWorker
func NewCBORPluginWorker(glue glue.Glue) (*CBORPluginWorker, error) {

	kaetzchenWorker := CBORPluginWorker{
		geo:         glue.Config().SphinxGeometry,
		glue:        glue,
		log:         glue.LogBackend().GetLogger("CBOR plugin worker"),
		pluginChans: make(PluginChans),
		clients:     make([]*cborplugin.Client, 0),
	}

	capaMap := make(map[string]bool)

	for _, pluginConf := range glue.Config().ServiceNode.CBORPluginKaetzchen {
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

		err := kaetzchenWorker.register(pluginConf)

		if err != nil {
			return nil, err
		}

		capaMap[capa] = true
	}
	return &kaetzchenWorker, nil
}

// RegisterKaetzchen adds a Kaetzchen service to the set of available Kaetzchen
func (k *CBORPluginWorker) RegisterKaetzchen(capa string) error {
	for _, kaetzchenConfig := range k.glue.Config().ServiceNode.CBORPluginKaetzchen {
		if kaetzchenConfig.Capability == capa {
			// verify that the plugin isn't already registered
			var endpoint [constants.RecipientIDLength]byte
			copy(endpoint[:], []byte(kaetzchenConfig.Endpoint))
			return k.register(kaetzchenConfig)
		}
	}
	return fmt.Errorf("provider: kaetzchen: '%v' not found in config", capa)
}

// UnregisterKaetzchen stops a CBORPluginKaetzczhen and removes it from the set of available Kaetzchen
func (k *CBORPluginWorker) UnregisterKaetzchen(capa string) error {
	k.Lock()
	defer k.Unlock()
	for _, kaetzchenConfig := range k.glue.Config().ServiceNode.CBORPluginKaetzchen {
		if kaetzchenConfig.Capability == capa {
			// verify that the plugin is already registered
			var endpoint [constants.RecipientIDLength]byte
			copy(endpoint[:], []byte(kaetzchenConfig.Endpoint))
			if !k.isKaetzchen(endpoint) {
				return fmt.Errorf("provider: kaetzchen: '%v' is not registered", capa)
			}

			// find the client plugin and halt it
			for _, client := range k.clients {
				if client.Capability() == capa {
					k.log.Debugf("Halting plugin client: %s", capa)
					go client.Halt() // unregister is called after the plugin has Halted
					return nil
				}
			}
		}
	}
	return fmt.Errorf("provider: CBORPluginKaetzchen: '%v' not found", capa)
}

func (k *CBORPluginWorker) register(pluginConf *config.CBORPluginKaetzchen) error {
	// hold lock while mutating pluginChans and clients
	k.Lock()
	defer k.Unlock()
	var endpoint [constants.RecipientIDLength]byte
	copy(endpoint[:], []byte(pluginConf.Endpoint))

	if k.isKaetzchen(endpoint) {
		return fmt.Errorf("provider: kaetzchen: '%v' is already registered", pluginConf.Capability)
	}

	// Add an infinite channel for this plugin.
	k.pluginChans[endpoint] = make(chan interface{}, InboundPacketsChannelSize)
	k.log.Noticef("Starting Kaetzchen plugin client: %s", pluginConf.Capability)

	var args []string
	if len(pluginConf.Config) > 0 {
		args = []string{}
		for key, val := range pluginConf.Config {
			args = append(args, fmt.Sprintf("-%s", key), val.(string))
		}
	}

	pluginClient, err := k.launch(pluginConf.Command, pluginConf.Capability, pluginConf.Endpoint, args)
	if err != nil {
		k.log.Error("Failed to start a plugin client: %s", err)
		return err
	}

	// Accumulate a list of all clients to facilitate clean shutdown.
	k.clients = append(k.clients, pluginClient)

	// Start the workers _after_ we have added all of the entries to pluginChans
	// otherwise the worker() goroutines race this thread.
	defer k.Go(func() {
		// pluginChans must exist for worker routine and OnKaetzchen
		k.worker(endpoint, pluginClient)
	})

	// start the sendworker
	defer k.Go(func() {
		k.sendworker(pluginClient)
	})

	// Unregister pluginClient when it halts
	defer k.Go(func() {
		<-pluginClient.HaltCh()
		k.unregister(endpoint, pluginClient)
	})
	return nil
}
