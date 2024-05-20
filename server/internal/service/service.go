// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel and David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package service implements the Katzenpost service node.
package service

import (
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

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

func (p *serviceNode) KaetzchenForPKI() (map[string]map[string]interface{}, error) {
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

	return merged, nil
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

	// Start the workers.
	for i := 0; i < cfg.Debug.NumServiceWorkers; i++ {
		p.Go(p.worker)
	}

	// monitor channel length
	go p.monitorChannelLen()

	isOk = true
	return p, nil
}

func (p *serviceNode) monitorChannelLen() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		instrument.GaugeChannelLength("server.service.ch", len(p.ch))
	}
}
