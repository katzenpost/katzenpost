// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel and David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/epochtime"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/katzenpost/katzenpost/server/spool"
	"github.com/katzenpost/katzenpost/server/spool/memspool"
)

const InboundPacketsChannelSize = 1000

type gateway struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	ch    chan interface{}
	spool spool.Spool

	lastFullLog atomic.Int64 // UnixNano of the last spool-full warning.
}

const spoolFullLogInterval = time.Minute

// storeFailed counts and logs a refused spool store.  A full spool is
// warned about at most once per spoolFullLogInterval, since a flood would
// otherwise log every packet; other failures stay at debug level.
func (p *gateway) storeFailed(pkt *packet.Packet, err error, otherReason string) {
	instrument.PacketsDropped()
	switch {
	case errors.Is(err, spool.ErrRecipientFull):
		instrument.PacketsDroppedByReason("gateway_spool_recipient_full")
	case errors.Is(err, spool.ErrFull):
		instrument.PacketsDroppedByReason("gateway_spool_full")
	default:
		instrument.PacketsDroppedByReason(otherReason)
		p.log.Debugf("Failed to store packet: %v (%v)", pkt.ID, err)
		return
	}
	now := time.Now().UnixNano()
	last := p.lastFullLog.Load()
	if now-last >= int64(spoolFullLogInterval) && p.lastFullLog.CompareAndSwap(last, now) {
		p.log.Warningf("Refusing to spool packet %v: %v (repeats are counted in katzenpost_dropped_reason_total, logged at most once per %v)", pkt.ID, err, spoolFullLogInterval)
	}
}

func (p *gateway) Halt() {
	p.Worker.Halt()

	close(p.ch)
	if p.spool != nil {
		p.spool.Close()
		p.spool = nil
	}
}

func (p *gateway) Spool() spool.Spool {
	return p.spool
}

func (p *gateway) AuthenticateClient(c *wire.PeerCredentials) bool {
	// Any peer that completes the wire protocol handshake is accepted.
	return true
}

func (p *gateway) OnPacket(pkt *packet.Packet) {
	select {
	case <-p.HaltCh():
		p.log.Debugf("Terminating gracefully.")
		return
	default:
	}
	select {
	case p.ch <- pkt:
	case <-p.HaltCh():
		p.log.Debugf("Terminating gracefully.")
		return
	}
}

// notifyListeners wakes the push-delivery sender on any listener that
// currently holds an authenticated connection for recipient, so it
// drains the spool entry we just stored. Broadcast to every listener
// because the recipient's connection (if any) could live on any of
// them; each listener's Notify is a cheap map lookup with a no-op miss.
func (p *gateway) notifyListeners(recipient []byte) {
	for _, listener := range p.glue.Listeners() {
		listener.Notify(recipient)
	}
}

func (p *gateway) connectedClients() (map[[sConstants.RecipientIDLength]byte]interface{}, error) {
	identities := make(map[[sConstants.RecipientIDLength]byte]interface{})
	for _, listener := range p.glue.Listeners() {
		listenerIdentities, err := listener.GetConnIdentities()
		if err != nil {
			return nil, err
		}

		for id, _ := range listenerIdentities {
			identities[id] = struct{}{}
		}
	}
	return identities, nil
}

func (g *gateway) gcEphemeralClients() {
	g.log.Debug("garbage collecting expired ephemeral clients")
	connectedClients, err := g.connectedClients()
	if err != nil {
		g.log.Errorf("wtf: %s", err)
		return
	}
	err = g.Spool().VacuumExpired(connectedClients)
	if err != nil {
		g.log.Errorf("wtf: %s", err)
		return
	}
}

func (p *gateway) worker() {
	maxDwell := time.Duration(p.glue.Config().Debug.GatewayDelay) * time.Millisecond

	defer p.log.Debugf("Halting Gateway worker.")

	ch := p.ch

	// Here we optionally set this GC timer. If unset the
	// channel remains nil and has no effect on the select
	// statement below. If set then the timer will periodically
	// write to the channel triggering our GC routine.
	var gcEphemeralClientGCTickerChan <-chan time.Time

	if p.glue.Config().Gateway != nil {
		ticker := time.NewTicker(epochtime.Period())
		gcEphemeralClientGCTickerChan = ticker.C
		defer ticker.Stop()
	}

	for {
		var pkt *packet.Packet
		select {
		case <-p.HaltCh():
			p.log.Debugf("Terminating gracefully.")
			return
		case <-gcEphemeralClientGCTickerChan:
			p.gcEphemeralClients()
			continue
		case e := <-ch:
			pkt = e.(*packet.Packet)
			instrument.GaugeChannelLength("gateway_incoming", len(ch))

			if dwellTime := time.Now().Sub(pkt.DispatchAt); dwellTime > maxDwell {
				p.log.Debugf("Dropping packet: %v (Spend %v in queue)", pkt.ID, dwellTime)
				instrument.PacketsDropped()
				instrument.PacketsDroppedByReason("gateway_dwell_exceeded")
				pkt.Dispose()
				continue
			}
		}

		if pkt == nil {
			continue
		}

		// Post-process the recipient.
		recipient := pkt.Recipient.ID[:]

		// The caller checks that the packet is either a SURB-Reply or a
		// user message, so anything that is not the former is the latter.
		if pkt.IsSURBReply() {
			p.onSURBReply(pkt, recipient)
		} else {
			p.onToUser(pkt, recipient)
		}
		pkt.Dispose()
	}
}

func (p *gateway) onSURBReply(pkt *packet.Packet, recipient []byte) {
	geo := p.glue.Config().SphinxGeometry
	if len(pkt.Payload) != geo.PayloadTagLength+geo.ForwardPayloadLength {
		p.log.Debugf("Refusing to store mis-sized SURB-Reply: %v (%v)", pkt.ID, len(pkt.Payload))
		instrument.PacketsDropped()
		instrument.PacketsDroppedByReason("gateway_surb_reply_missized")
		return
	}

	// Store the payload in the spool.
	if err := p.spool.StoreSURBReply(recipient, &pkt.SurbReply.ID, pkt.Payload); err != nil {
		p.storeFailed(pkt, err, "gateway_spool_surb_reply_failed")
		return
	}
	p.log.Debugf("Stored SURB-Reply: %v", pkt.ID)
	p.notifyListeners(recipient)
}

func (p *gateway) onToUser(pkt *packet.Packet, recipient []byte) {
	ct, surb, err := packet.ParseForwardPacket(pkt)
	if err != nil {
		p.log.Debugf("Dropping packet: %v (%v)", pkt.ID, err)
		instrument.PacketsDropped()
		instrument.PacketsDroppedByReason("gateway_parse_forward_failed")
		return
	}

	// Store the ciphertext in the spool.
	if err := p.spool.StoreMessage(recipient, ct); err != nil {
		p.storeFailed(pkt, err, "gateway_spool_message_failed")
		return
	}
	p.notifyListeners(recipient)

	// Iff there is a SURB, generate a SURB-ACK and schedule.
	if surb != nil {
		ackPkt, err := packet.NewPacketFromSURB(surb, nil, p.glue.Config().SphinxGeometry)
		if err != nil {
			p.log.Debugf("Failed to generate SURB-ACK: %v (%v)", pkt.ID, err)
			instrument.PacketsDropped()
			instrument.PacketsDroppedByReason("gateway_surb_ack_failed")
			return
		}

		p.log.Debugf("Handing off newly generated SURB-ACK: %v (Src:%v)", ackPkt.ID, pkt.ID)
		p.glue.Scheduler().OnPacket(ackPkt)
	} else {
		p.log.Debugf("Stored Message: %v (No SURB)", pkt.ID)
	}
}

// removeOldSpoolDB deletes the on-disk spool of older versions, which is no
// longer read; clients fetch the messages it held again from storage.
func (p *gateway) removeOldSpoolDB(cfg *config.Config) {
	path := filepath.Join(cfg.Server.DataDir, "spool.db") // The old default.
	if sdb := cfg.Gateway.SpoolDB; sdb != nil && sdb.Bolt != nil && sdb.Bolt.SpoolDB != "" {
		path = sdb.Bolt.SpoolDB
	}
	// Older versions refused a relative path, so one never named a spool.
	if !filepath.IsAbs(path) {
		return
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	if err := os.Remove(path); err != nil {
		p.log.Warningf("Failed to remove the old spool file %s: %v", path, err)
		return
	}
	p.log.Noticef("Removed the old spool file %s (%d bytes); the spool is kept in memory.", path, fi.Size())
}

// New constructs a new provider instance.
func New(glue glue.Glue) (glue.Gateway, error) {
	p := &gateway{
		glue: glue,
		log:  glue.LogBackend().GetLogger("gateway"),
		ch:   make(chan interface{}, InboundPacketsChannelSize),
	}

	cfg := glue.Config()

	isOk := false
	defer func() {
		if !isOk {
			p.Halt()
		}
	}()

	if cfg.Gateway.SpoolDB != nil {
		p.log.Noticef("The user message spool is kept in memory; the [Gateway.SpoolDB] settings are ignored and can be removed.")
	}
	p.removeOldSpoolDB(cfg)
	p.spool = memspool.New(cfg.Gateway.SpoolMaxRecipientBytes, cfg.Gateway.SpoolMaxBytes)
	p.log.Noticef("User message spool limits: %d bytes per recipient, %d bytes in total.", cfg.Gateway.SpoolMaxRecipientBytes, cfg.Gateway.SpoolMaxBytes)

	// Start the workers.
	for i := 0; i < cfg.Debug.NumGatewayWorkers; i++ {
		p.Go(p.worker)
	}

	isOk = true
	return p, nil
}
