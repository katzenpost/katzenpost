// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel and David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package service implements the Katzenpost service node.
package service

import (
	"strings"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/katzenpost/katzenpost/server/internal/service/kaetzchen"
)

const InboundPacketsChannelSize = 1000

type serviceNode struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	ch chan interface{}

	kaetzchenWorker           *kaetzchen.KaetzchenWorker
	cborPluginKaetzchenWorker *kaetzchen.CBORPluginWorker
}

func (p *serviceNode) Halt() {
	p.Worker.Halt()

	close(p.ch)
	p.kaetzchenWorker.Halt()
	p.cborPluginKaetzchenWorker.Halt()
}

func (p *serviceNode) OnPacket(pkt *packet.Packet) {
	p.ch <- pkt
}

func (p *serviceNode) KaetzchenForPKI() (map[string]map[string]interface{}, map[string]map[string]interface{}, error) {
	map1 := p.kaetzchenWorker.KaetzchenForPKI()
	map2 := p.cborPluginKaetzchenWorker.KaetzchenForPKI()

	// merge sets, panic on duplicate
	setsToMerge := []map[kaetzchen.PluginName]kaetzchen.PluginParameters{
		map1, map2,
	}

	merged := make(map[kaetzchen.PluginName]kaetzchen.PluginParameters)

	for _, currentSet := range setsToMerge {
		for k, v := range currentSet {
			if _, ok := merged[k]; ok {
				p.log.Debug("WARNING: duplicate plugin entries")
				panic("WARNING: duplicate plugin entries")
			}
			merged[k] = v
		}
	}

	kaetzchenAdvertizedData := make(map[string]map[string]interface{})
	cfg := p.glue.Config()
	for _, v := range cfg.ServiceNode.CBORPluginKaetzchen {
		kaetzchenAdvertizedData[v.Capability] = v.PKIAdvertizedData[v.Capability]
	}

	return kaetzchenAdvertizedData, merged, nil
}

func (p *serviceNode) worker() {
	maxDwell := time.Duration(p.glue.Config().Debug.ServiceDelay) * time.Millisecond

	defer p.log.Debugf("Halting Service worker.")

	ch := p.ch

	for {
		var pkt *packet.Packet
		select {
		case <-p.HaltCh():
			p.log.Debugf("Terminating gracefully.")
			return
		case e := <-ch:
			pkt = e.(*packet.Packet)

			if dwellTime := time.Now().Sub(pkt.DispatchAt); dwellTime > maxDwell {
				p.log.Debugf("Dropping packet: %v (Spend %v in queue)", pkt.ID, dwellTime)
				instrument.PacketsDropped()
				pkt.Dispose()
				continue
			}
		}

		if pkt == nil {
			continue
		}

		// Kaetzchen endpoints are published in the PKI and are never
		// user-facing, so omit the recipient-post processing.  If clients
		// are written under the assumption that Kaetzchen addresses are
		// normalized, that's their problem.
		if p.kaetzchenWorker.IsKaetzchen(pkt.Recipient.ID) {
			// Packet is destined for a Kaetzchen auto-responder agent, and
			// can't be a SURB-Reply.
			if pkt.IsSURBReply() {
				p.log.Debugf("Dropping packet: %v (SURB-Reply for Kaetzchen)", pkt.ID)
				instrument.PacketsDropped()
				pkt.Dispose()
			} else {
				// Note that we pass ownership of pkt to p.kaetzchenWorker
				// which will take care to dispose of it.
				p.kaetzchenWorker.OnKaetzchen(pkt)
			}
			continue
		}

		if p.cborPluginKaetzchenWorker.IsKaetzchen(pkt.Recipient.ID) {
			if pkt.IsSURBReply() {
				p.log.Debugf("Dropping packet: %v (SURB-Reply for Kaetzchen)", pkt.ID)
				instrument.PacketsDropped()
				pkt.Dispose()
			} else {
				// Note that we pass ownership of pkt to p.kaetzchenWorker
				// which will take care to dispose of it.
				p.cborPluginKaetzchenWorker.OnKaetzchen(pkt)
			}
			continue
		}

		p.log.Debugf("Dropping packet: %v because recipient %x is not found", pkt.ID, pkt.Recipient.ID)
		instrument.PacketsDropped()
		pkt.Dispose()
	}
}

func (p *serviceNode) isKaetzchenConfigured(capa string) bool {
	for _, v := range p.glue.Config().ServiceNode.Kaetzchen {
		// do not enable a plugin explicitely disabled by configuration
		if v.Capability == capa && !v.Disable {
			return true
		}
	}
	return false
}

func (p *serviceNode) isKaetzchenRegistered(capa string) bool {
	kpki := p.kaetzchenWorker.KaetzchenForPKI()
	if _, ok := kpki[capa]; ok {
		return true
	}
	return false
}

func (p *serviceNode) isCBORKaetzchenConfigured(capa string) bool {
	// check whether the capability is a CBORPlugin
	for _, pluginConf := range p.glue.Config().ServiceNode.CBORPluginKaetzchen {
		if capa == pluginConf.Capability && !pluginConf.Disable {
			return true
		}
	}
	return false
}

func (p *serviceNode) isCBORKaetzchenRegistered(capa string) bool {
	// get endpoint from config
	for _, pluginConf := range p.glue.Config().ServiceNode.CBORPluginKaetzchen {
		if capa == pluginConf.Capability && !pluginConf.Disable {
			var endpoint [constants.RecipientIDLength]byte
			copy(endpoint[:], []byte(pluginConf.Endpoint))
			return p.cborPluginKaetzchenWorker.IsKaetzchen(endpoint)
		}
	}
	return false
}

// handler for STOP_KAETZCHEN
func (p *serviceNode) onStopKaetzchen(c *thwack.Conn, l string) error {
	p.Lock()
	defer p.Unlock()

	sp := strings.Split(l, " ")

	if len(sp) != 2 {
		c.Log().Debugf("STOP_KAETZCHEN invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}
	capa := sp[1]
	// check internal plugins
	if p.isKaetzchenConfigured(capa) && p.isKaetzchenRegistered(capa) {
		err := p.kaetzchenWorker.UnregisterKaetzchen(capa)
		if err != nil {
			p.log.Errorf("provider: Kaetzchen: '%v'", err)
			return c.WriteReply(thwack.StatusTransactionFailed)
		}
		return c.Writer().PrintfLine("%v %v", thwack.StatusOk, capa)
	}
	// check external plugins
	if p.isCBORKaetzchenConfigured(capa) && !p.isCBORKaetzchenRegistered(capa) {
		c.Log().Debugf("START_KAETZCHEN failed: %v not running", capa)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}
	err := p.cborPluginKaetzchenWorker.UnregisterKaetzchen(capa)
	if err != nil {
		p.log.Errorf("provider: Kaetzchen: '%v'", err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}
	return c.Writer().PrintfLine("%v %v", thwack.StatusOk, capa)
}

// handler for START_KAETZCHEN
func (p *serviceNode) onStartKaetzchen(c *thwack.Conn, l string) error {
	p.Lock()
	defer p.Unlock()

	sp := strings.Split(l, " ")

	if len(sp) != 2 {
		c.Log().Debugf("START_KAETZCHEN invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	capa := sp[1]

	// check internal plugins
	if p.isKaetzchenConfigured(capa) && !p.isKaetzchenRegistered(capa) {
		err := p.kaetzchenWorker.RegisterKaetzchen(capa)
		if err != nil {
			p.log.Errorf("provider: Kaetzchen: '%v'", err)
			return c.WriteReply(thwack.StatusTransactionFailed)
		}
		return c.Writer().PrintfLine("%v %v", thwack.StatusOk, capa)
	}
	// check external plugins
	if p.isCBORKaetzchenConfigured(capa) && p.isCBORKaetzchenRegistered(capa) {
		c.Log().Debugf("START_KAETZCHEN failed: %v already running", capa)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}
	err := p.cborPluginKaetzchenWorker.RegisterKaetzchen(capa)
	if err != nil {
		p.log.Errorf("provider: Kaetzchen: '%v'", err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}
	return c.Writer().PrintfLine("%v %v", thwack.StatusOk, capa)
}

// New constructs a new provider instance.
func New(glue glue.Glue) (glue.ServiceNode, error) {
	kaetzchenWorker, err := kaetzchen.New(glue)
	if err != nil {
		return nil, err
	}
	cborPluginWorker, err := kaetzchen.NewCBORPluginWorker(glue)
	if err != nil {
		return nil, err
	}
	p := &serviceNode{
		glue:                      glue,
		log:                       glue.LogBackend().GetLogger("provider"),
		ch:                        make(chan interface{}, InboundPacketsChannelSize),
		kaetzchenWorker:           kaetzchenWorker,
		cborPluginKaetzchenWorker: cborPluginWorker,
	}

	cfg := glue.Config()

	isOk := false
	defer func() {
		if !isOk {
			p.Halt()
		}
	}()

	// Wire in the management related commands.
	if cfg.Management.Enable {
		const (
			cmdStopKaetzchen  = "STOP_KAETZCHEN"
			cmdStartKaetzchen = "START_KAETZCHEN"
		)

		glue.Management().RegisterCommand(cmdStopKaetzchen, p.onStopKaetzchen)
		glue.Management().RegisterCommand(cmdStartKaetzchen, p.onStartKaetzchen)
	}

	// Start the workers.
	for i := 0; i < cfg.Debug.NumServiceWorkers; i++ {
		p.Go(p.worker)
	}

	isOk = true
	return p, nil
}
