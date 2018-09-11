// plugins.go - plugin system for kaetzchen services
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
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/katzenpost/core/monotime"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/internal/packet"
	kplugin "github.com/katzenpost/server/plugin"
	"golang.org/x/text/secure/precis"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

// PluginKaetzchenWorker is similar to Kaetzchen worker but uses
// the go-plugin system to implement services in external programs.
// These plugins can be written in any language as long as it speaks gRPC
// over unix domain socket.
type PluginKaetzchenWorker struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	pluginChan map[[sConstants.RecipientIDLength]byte]*channels.InfiniteChannel
	clients    []*plugin.Client
	forPKI     map[string]map[string]interface{}
}

// OnKaetzchen enqueues the pkt for processing by our thread pool of plugins.
func (k *PluginKaetzchenWorker) OnKaetzchen(pkt *packet.Packet) {
	handlerCh, ok := k.pluginChan[pkt.Recipient.ID]
	if !ok {
		k.log.Debugf("Failed to find handler. Dropping Kaetzchen request: %v", pkt.ID)
		return
	}
	handlerCh.In() <- pkt
}

func (k *PluginKaetzchenWorker) worker(recipient [sConstants.RecipientIDLength]byte, pluginClient kplugin.KaetzchenPluginInterface) {
	// Kaetzchen delay is our max dwell time.
	maxDwell := time.Duration(k.glue.Config().Debug.KaetzchenDelay) * time.Millisecond

	defer k.log.Debugf("Halting Kaetzchen worker.")

	handlerCh, ok := k.pluginChan[recipient]
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
			k.killAllClients()
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

func (k *PluginKaetzchenWorker) killAllClients() {
	for _, client := range k.clients {
		go client.Kill()
	}
}

func (k *PluginKaetzchenWorker) processKaetzchen(pkt *packet.Packet, pluginClient kplugin.KaetzchenPluginInterface) {
	defer pkt.Dispose()

	ct, surb, err := packet.ParseForwardPacket(pkt)
	if err != nil {
		k.log.Debugf("Dropping Kaetzchen request: %v (%v)", pkt.ID, err)
		return
	}

	var resp []byte
	respStr, err := pluginClient.OnRequest(pkt.ID, ct, surb != nil)
	switch {
	case err == nil:
	case err == ErrNoResponse:
		k.log.Debugf("Processed Kaetzchen request: %v (No response)", pkt.ID)
		return
	default:
		k.log.Debugf("Failed to handle Kaetzchen request: %v (%v)", pkt.ID, err)
		return
	}
	resp = []byte(respStr)

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

// KaetzchenForPKI returns the plugins Parameters map for publication in the PKI doc.
func (k *PluginKaetzchenWorker) KaetzchenForPKI() map[string]map[string]interface{} {
	if len(k.pluginChan) == 0 {
		k.log.Debug("wtf is pluginChan len 0?")
		return nil
	}
	return k.forPKI
}

// IsKaetzchen returns true if the given recipient is one of our workers.
func (k *PluginKaetzchenWorker) IsKaetzchen(recipient [sConstants.RecipientIDLength]byte) bool {
	_, ok := k.pluginChan[recipient]
	return ok
}

func (k *PluginKaetzchenWorker) launch(command string, args []string) (kplugin.KaetzchenPluginInterface, *plugin.Client, error) {
	var clientCfg *plugin.ClientConfig
	clientCfg = &plugin.ClientConfig{
		HandshakeConfig: kplugin.Handshake,
		Plugins:         kplugin.PluginMap,
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC},
	}

	var strBuilder strings.Builder
	strBuilder.WriteString(fmt.Sprintf("Launching command: %s ", command))
	if args == nil {
		clientCfg.Cmd = exec.Command(command)
	} else {
		clientCfg.Cmd = exec.Command(command, args...)
		strBuilder.WriteString(strings.Join(args, " "))
	}
	k.log.Debug(strBuilder.String())

	client := plugin.NewClient(clientCfg)

	// Connect via RPC
	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, nil, err
	}

	// Request the plugin
	raw, err := rpcClient.Dispense(kplugin.KaetzchenService)
	if err != nil {
		client.Kill()
		return nil, nil, err
	}
	service, ok := raw.(kplugin.KaetzchenPluginInterface)
	if !ok {
		client.Kill()
		return nil, nil, errors.New("WARNING: plugin not loaded, type assertion failure for KaetzchenPluginInterface")
	}
	return service, client, err
}

// NewPluginKaetzchenWorker returns a new PluginKaetzchenWorker
func NewPluginKaetzchenWorker(glue glue.Glue) (*PluginKaetzchenWorker, error) {

	kaetzchenWorker := PluginKaetzchenWorker{
		glue:       glue,
		log:        glue.LogBackend().GetLogger("plugin_kaetzchen_worker"),
		pluginChan: make(map[[sConstants.RecipientIDLength]byte]*channels.InfiniteChannel),
		clients:    make([]*plugin.Client, 0),
		forPKI:     make(map[string]map[string]interface{}),
	}

	capaMap := make(map[string]bool)

	for _, pluginConf := range glue.Config().Provider.PluginKaetzchen {
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
		kaetzchenWorker.pluginChan[endpoint] = channels.NewInfiniteChannel()

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

			pluginClient, client, err := kaetzchenWorker.launch(pluginConf.Command, args)
			if err != nil {
				kaetzchenWorker.log.Error("Failed to start a plugin client.")
				return nil, err
			}

			if !gotParams {
				// just once we call the Parameters method on the plugin
				// and use that info to populate our forPKI map which
				// ends up populating the PKI document
				p, err := pluginClient.Parameters()
				if err != nil {
					return nil, err
				}
				for key, value := range p {
					params[key] = value
				}
				params[ParameterEndpoint] = pluginConf.Endpoint
				gotParams = true
			}

			// Accumulate a list of all clients to facilitate clean shutdown.
			kaetzchenWorker.clients = append(kaetzchenWorker.clients, client)

			// Start the worker.
			worker := func() {
				kaetzchenWorker.worker(endpoint, pluginClient)
			}
			kaetzchenWorker.Go(worker)
		}

		kaetzchenWorker.forPKI[capa] = params
		capaMap[capa] = true
	}

	return &kaetzchenWorker, nil
}
