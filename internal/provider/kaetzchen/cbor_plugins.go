// cbor_plugins.go - cbor plugin system for kaetzchen services
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

// Package kaetzchen implements support for provider side auto-responder
// agents.
package kaetzchen

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/katzenpost/core/monotime"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/cborplugin"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/internal/packet"
	"golang.org/x/text/secure/precis"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

// PluginChans maps from Recipient ID to channel.
type PluginChans = map[[sConstants.RecipientIDLength]byte]*channels.InfiniteChannel

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
// CBOR over HTTP over UNIX domain socket to talk to plugins.
type CBORPluginWorker struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	haltOnce    sync.Once
	pluginChans PluginChans
	clients     []*cborplugin.Client
	forPKI      ServiceMap
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

func (k *CBORPluginWorker) worker(recipient [sConstants.RecipientIDLength]byte, pluginClient cborplugin.ServicePlugin) {
	// Kaetzchen delay is our max dwell time.
	maxDwell := time.Duration(k.glue.Config().Debug.KaetzchenDelay) * time.Millisecond

	defer k.haltOnce.Do(k.haltAllClients)

	handlerCh, ok := k.pluginChans[recipient]
	if !ok {
		k.log.Debugf("Failed to find handler. Dropping Kaetzchen request: %v", recipient)
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
				pkt.Dispose()
				continue
			}
		}

		k.processKaetzchen(pkt, pluginClient)
	}
}

func (k *CBORPluginWorker) haltAllClients() {
	k.log.Debug("Halting plugin clients.")
	for _, client := range k.clients {
		go client.Halt()
	}
}

func (k *CBORPluginWorker) processKaetzchen(pkt *packet.Packet, pluginClient cborplugin.ServicePlugin) {
	defer pkt.Dispose()

	ct, surb, err := packet.ParseForwardPacket(pkt)
	if err != nil {
		k.log.Debugf("Dropping Kaetzchen request: %v (%v)", pkt.ID, err)
		return
	}

	resp, err := pluginClient.OnRequest(&cborplugin.Request{
		ID:      pkt.ID,
		Payload: ct,
		HasSURB: surb != nil,
	})
	switch err {
	case nil:
	case ErrNoResponse:
		k.log.Debugf("Processed Kaetzchen request: %v (No response)", pkt.ID)
		return
	default:
		k.log.Debugf("Failed to handle Kaetzchen request: %v (%v), response: %s", pkt.ID, err, resp)
		return
	}
	if len(resp) == 0 {
		k.log.Debugf("No reply from Kaetzchen: %v", pkt.ID)
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
		return
	}
	k.log.Debugf("No SURB provided: %v", pkt.ID)
}

// KaetzchenForPKI returns the plugins Parameters map for publication in the PKI doc.
func (k *CBORPluginWorker) KaetzchenForPKI() ServiceMap {
	return k.forPKI
}

// IsKaetzchen returns true if the given recipient is one of our workers.
func (k *CBORPluginWorker) IsKaetzchen(recipient [sConstants.RecipientIDLength]byte) bool {
	_, ok := k.pluginChans[recipient]
	return ok
}

func (k *CBORPluginWorker) launch(command string, args []string) (*cborplugin.Client, error) {
	k.log.Debugf("Launching plugin: %s", command)
	plugin := cborplugin.New(k.log)
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
		forPKI:      make(ServiceMap),
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
		if len(rawEp) == 0 || len(rawEp) > sConstants.RecipientIDLength {
			return nil, fmt.Errorf("provider: Kaetzchen: '%v' invalid endpoint, length out of bounds", capa)
		}

		// Add an infinite channel for this plugin.
		var endpoint [sConstants.RecipientIDLength]byte
		copy(endpoint[:], rawEp)
		kaetzchenWorker.pluginChans[endpoint] = channels.NewInfiniteChannel()

		// Add entry from this plugin for the PKI.
		params := make(map[string]interface{})
		gotParams := false

		// Start the plugin clients.
		for i := 0; i < pluginConf.MaxConcurrency; i++ {
			kaetzchenWorker.log.Noticef("Starting Kaetzchen plugin client: %s %d", capa, i)

			var args []string
			if len(pluginConf.Config) > 0 {
				args = []string{}
				for key, val := range pluginConf.Config {
					args = append(args, fmt.Sprintf("-%s", key), val.(string))
				}
			}

			pluginClient, err := kaetzchenWorker.launch(pluginConf.Command, args)
			if err != nil {
				kaetzchenWorker.log.Error("Failed to start a plugin client: %s", err)
				return nil, err
			}

			if !gotParams {
				// just once we call the Parameters method on the plugin
				// and use that info to populate our forPKI map which
				// ends up populating the PKI document
				p := pluginClient.GetParameters()
				if p != nil {
					for key, value := range *p {
						params[key] = value
					}
				}
				params[ParameterEndpoint] = pluginConf.Endpoint
				gotParams = true
			}

			// Accumulate a list of all clients to facilitate clean shutdown.
			kaetzchenWorker.clients = append(kaetzchenWorker.clients, pluginClient)

			// Start the worker.
			kaetzchenWorker.Go(func() {
				kaetzchenWorker.worker(endpoint, pluginClient)
			})
		}

		kaetzchenWorker.forPKI[capa] = params
		capaMap[capa] = true
	}

	return &kaetzchenWorker, nil
}
