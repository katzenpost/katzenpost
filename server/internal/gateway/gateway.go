// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/katzenpost/katzenpost/server/internal/sqldb"
	"github.com/katzenpost/katzenpost/server/spool"
	"github.com/katzenpost/katzenpost/server/spool/boltspool"
	"github.com/katzenpost/katzenpost/server/userdb"
	"github.com/katzenpost/katzenpost/server/userdb/boltuserdb"
	"github.com/katzenpost/katzenpost/server/userdb/externuserdb"
)

const InboundPacketsChannelSize = 1000

type gateway struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	ch     chan interface{}
	sqlDB  *sqldb.SQLDB
	userDB userdb.UserDB
	spool  spool.Spool
}

func (p *gateway) Halt() {
	p.Worker.Halt()

	close(p.ch)
	if p.userDB != nil {
		p.userDB.Close()
		p.userDB = nil
	}
	if p.spool != nil {
		p.spool.Close()
		p.spool = nil
	}
	if p.sqlDB != nil {
		p.sqlDB.Close()
	}
}

func (p *gateway) Spool() spool.Spool {
	return p.spool
}

func (p *gateway) UserDB() userdb.UserDB {
	return p.userDB
}

func (p *gateway) AuthenticateClient(c *wire.PeerCredentials) bool {
	isValid := p.userDB.IsValid(c.AdditionalData, c.PublicKey)
	if !isValid {
		blob, err := c.PublicKey.MarshalBinary()
		if err != nil {
			panic(err)
		}
		if len(c.AdditionalData) == sConstants.NodeIDLength {
			p.log.Errorf("Authentication failed: User: '%x', Key: '%x' (Probably a peer)", c.AdditionalData, hash.Sum256(blob))
		} else {
			p.log.Errorf("Authentication failed: User: '%x', Key: '%x'", c.AdditionalData, hash.Sum256(blob))
		}
	}
	return isValid
}

func (p *gateway) OnPacket(pkt *packet.Packet) {
	p.ch <- pkt
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
	err = g.Spool().VacuumExpired(g.UserDB(), connectedClients)
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
		ticker := time.NewTicker(epochtime.Period)
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

		// Post-process the recipient.
		recipient := pkt.Recipient.ID[:]

		// Ensure the packet is for a valid recipient.
		if !p.userDB.Exists(recipient) {
			p.log.Debugf("Dropping packet: %v (Invalid Recipient: '%v')", pkt.ID, utils.ASCIIBytesToPrintString(recipient))
			instrument.PacketsDropped()
			pkt.Dispose()
			continue
		}

		// Process the packet based on type.
		if pkt.IsSURBReply() {
			p.onSURBReply(pkt, recipient)
			pkt.Dispose()
			continue
		} else {
			// Caller checks that the packet is either a SURB-Reply or a user
			// message, so this must be the latter.
			p.onToUser(pkt, recipient)
			pkt.Dispose()
			continue
		}

		p.log.Debugf("Dropping packet: %v (Invalid Recipient: '%x')", pkt.ID, recipient)
		instrument.PacketsDropped()
		pkt.Dispose()

	}
}

func (p *gateway) onSURBReply(pkt *packet.Packet, recipient []byte) {
	geo := p.glue.Config().SphinxGeometry
	if len(pkt.Payload) != geo.PayloadTagLength+geo.ForwardPayloadLength {
		p.log.Debugf("Refusing to store mis-sized SURB-Reply: %v (%v)", pkt.ID, len(pkt.Payload))
		return
	}

	// Store the payload in the spool.
	if err := p.spool.StoreSURBReply(recipient, &pkt.SurbReply.ID, pkt.Payload); err != nil {
		p.log.Debugf("Failed to store SURB-Reply: %v (%v)", pkt.ID, err)
	} else {
		p.log.Debugf("Stored SURB-Reply: %v", pkt.ID)
	}
}

func (p *gateway) onToUser(pkt *packet.Packet, recipient []byte) {
	ct, surb, err := packet.ParseForwardPacket(pkt)
	if err != nil {
		p.log.Debugf("Dropping packet: %v (%v)", pkt.ID, err)
		instrument.PacketsDropped()
		return
	}

	// Store the ciphertext in the spool.
	if err := p.spool.StoreMessage(recipient, ct); err != nil {
		p.log.Debugf("Failed to store message payload: %v (%v)", pkt.ID, err)
		return
	}

	// Iff there is a SURB, generate a SURB-ACK and schedule.
	if surb != nil {
		ackPkt, err := packet.NewPacketFromSURB(pkt, surb, nil, p.glue.Config().SphinxGeometry)
		if err != nil {
			p.log.Debugf("Failed to generate SURB-ACK: %v (%v)", pkt.ID, err)
			return
		}

		p.log.Debugf("Handing off newly generated SURB-ACK: %v (Src:%v)", ackPkt.ID, pkt.ID)
		p.glue.Scheduler().OnPacket(ackPkt)
	} else {
		p.log.Debugf("Stored Message: %v (No SURB)", pkt.ID)
	}
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

	var err error
	if cfg.Gateway.SQLDB != nil {
		if cfg.Gateway.UserDB.Backend == config.BackendSQL || cfg.Gateway.SpoolDB.Backend == config.BackendSQL {
			p.sqlDB, err = sqldb.New(glue)
			if err != nil {
				return nil, err
			}
		} else {
			p.log.Warningf("SQL database configured but not used for the User or Spool databases.")
		}
	}

	switch cfg.Gateway.UserDB.Backend {
	case config.BackendBolt:
		p.userDB, err = boltuserdb.New(cfg.Gateway.UserDB.Bolt.UserDB, schemes.ByName(cfg.Server.WireKEM), boltuserdb.WithTrustOnFirstUse())
	case config.BackendExtern:
		p.userDB, err = externuserdb.New(cfg.Gateway.UserDB.Extern.GatewayURL, schemes.ByName(cfg.Server.WireKEM))
	case config.BackendSQL:
		if p.sqlDB != nil {
			p.userDB, err = p.sqlDB.UserDB()
		} else {
			err = errors.New("gateway: SQL UserDB backend with no SQL database")
		}
	default:
		return nil, fmt.Errorf("gateway: Unknown UserDB backend: %v", cfg.Gateway.UserDB.Backend)
	}
	if err != nil {
		return nil, err
	}

	switch cfg.Gateway.SpoolDB.Backend {
	case config.BackendBolt:
		p.spool, err = boltspool.New(cfg.Gateway.SpoolDB.Bolt.SpoolDB)
	case config.BackendSQL:
		if p.sqlDB != nil {
			p.spool = p.sqlDB.Spool()
		} else {
			err = errors.New("gateway: SQL SpoolDB backend with no SQL database")
		}
	default:
		err = fmt.Errorf("gateway: Unknown SpoolDB backend: %v", cfg.Gateway.SpoolDB.Backend)
	}
	if err != nil {
		return nil, err
	}

	// Purge spools that belong to users that no longer exist in the user db.
	if err = p.spool.Vacuum(p.userDB); err != nil {
		return nil, err
	}

	// Start the workers.
	for i := 0; i < cfg.Debug.NumGatewayWorkers; i++ {
		p.Go(p.worker)
	}

	// monitor channel length
	instrument.MonitorChannelLen("server.gateway.ch", p.HaltCh(), p.ch)

	isOk = true
	return p, nil
}
