// scheduler.go - Katzenpost server provider backend.
// Copyright (C) 2017  Yawning Angel.
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

package server

import (
	"bytes"
	"strings"
	"sync"

	"github.com/eapache/channels"
	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/core/thwack"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/server/spool"
	"github.com/katzenpost/server/spool/boltspool"
	"github.com/katzenpost/server/userdb"
	"github.com/katzenpost/server/userdb/boltuserdb"
	"github.com/op/go-logging"
)

type provider struct {
	sync.Mutex
	sync.WaitGroup

	s      *Server
	ch     *channels.InfiniteChannel
	userDB userdb.UserDB
	spool  spool.Spool
	log    *logging.Logger

	haltCh chan interface{}
}

func (p *provider) halt() {
	close(p.haltCh)
	p.Wait()

	p.ch.Close()
	if p.userDB != nil {
		p.userDB.Close()
		p.userDB = nil
	}
	if p.spool != nil {
		p.spool.Close()
		p.spool = nil
	}
}

func (p *provider) authenticateClient(c *wire.PeerCredentials) bool {
	isValid := p.userDB.IsValid(c.AdditionalData, c.PublicKey)
	p.log.Debugf("Auth: User: '%v', Key: '%v': %v", asciiBytesToPrintString(c.AdditionalData), c.PublicKey, isValid)
	return isValid
}

func (p *provider) onPacket(pkt *packet) {
	ch := p.ch.In()
	ch <- pkt
}

func (p *provider) worker() {
	defer func() {
		p.log.Debugf("Halting Provider worker.")
		p.Done()
	}()

	ch := p.ch.Out()

	for {
		var pkt *packet
		select {
		case <-p.haltCh:
			p.log.Debugf("Terminating gracefully.")
			return
		case e := <-ch:
			pkt = e.(*packet)
		}

		// Sanity check the packet payload length.
		if len(pkt.payload) != constants.ForwardPayloadLength {
			p.log.Debugf("Dropping packet: %v (Invalid payload length: '%v')", pkt.id, len(pkt.payload))
			pkt.dispose()
			continue
		}

		// Fix the recipient by trimming off the trailing NUL bytes.
		recipient := bytes.TrimRight(pkt.recipient.ID[:], "\x00")

		// Ensure the packet is for a valid recipient.
		if !p.userDB.Exists(recipient) {
			p.log.Debugf("Dropping packet: %v (Invalid Recipient: '%v')", pkt.id, asciiBytesToPrintString(recipient))
			pkt.dispose()
			continue
		}

		// All of the store operations involve writing to the database which
		// won't really benefit from concurrency.
		if pkt.isSURBReply() {
			p.onSURBReply(pkt, recipient)
		} else {
			// Caller checks that the packet is either a SURBReply or a user
			// message, so this must be the latter.
			p.onToUser(pkt, recipient)
		}

		pkt.dispose()
	}
}

func (p *provider) onSURBReply(pkt *packet, recipient []byte) {
	if len(pkt.payload) != constants.ForwardPayloadLength {
		p.log.Debugf("Refusing to store mis-sized SURB-Reply: %v", len(pkt.payload))
		return
	}

	// Store the payload in the spool.
	if err := p.spool.StoreSURBReply(recipient, &pkt.surbReply.ID, pkt.payload); err != nil {
		p.log.Debugf("Failed to store SURBReply: %v (%v)", pkt.id, err)
	} else {
		p.log.Debugf("Stored SURBReply: %v", pkt.id)
	}
}

func (p *provider) onToUser(pkt *packet, recipient []byte) {
	const (
		hdrLength    = constants.SphinxPlaintextHeaderLength + sphinx.SURBLength
		flagsPadding = 0
		flagsSURB    = 1
		reserved     = 0
	)

	// Parse the payload, which should be a valid BlockSphinxPlaintext.
	b := pkt.payload
	if len(b) < hdrLength {
		p.log.Debugf("Dropping packet: %v (Truncated message block)", pkt.id)
		return
	}
	if b[1] != reserved {
		p.log.Debugf("Dropping packet: %v (Invalid message reserved: 0x%02x)", pkt.id, b[1])
		return
	}
	ct := b[hdrLength:]
	var surb []byte
	switch b[0] {
	case flagsPadding:
	case flagsSURB:
		surb = b[constants.SphinxPlaintextHeaderLength:hdrLength]
	default:
		p.log.Debugf("Dropping packet: %v (Invalid message flags: 0x%02x)", pkt.id, b[0])
		return
	}
	if len(ct) != constants.UserForwardPayloadLength {
		p.log.Debugf("Refusing to store mis-sized user payload: %v", len(ct))
		return
	}

	// Store the ciphertext in the spool.
	if err := p.spool.StoreMessage(recipient, ct); err != nil {
		p.log.Debugf("Failed to store message payload: %v (%v)", pkt.id, err)
		return
	}

	// Iff there is a SURB, generate a SURB-ACK, and schedule.
	if surb != nil {
		// Build the SURB-ACK from the SURB.
		//
		// TODO/perf: This is a crypto operation and can be made concurrent,
		// the logical place for this is probably the crypto workers.
		var ackPayload [constants.ForwardPayloadLength]byte
		rawAckPkt, firstHop, err := sphinx.NewPacketFromSURB(surb, ackPayload[:])
		if err != nil {
			p.log.Debugf("Failed to generate SURB-ACK: %v (%v)", pkt.id, err)
			return
		}

		// Build the packet structure for the SURB-ACK.
		ackPkt := newPacket()
		ackPkt.copyToRaw(rawAckPkt)
		ackPkt.cmds = make([]commands.RoutingCommand, 0, 2)

		nextHopCmd := new(commands.NextNodeHop)
		copy(nextHopCmd.ID[:], firstHop[:])
		ackPkt.cmds = append(ackPkt.cmds, nextHopCmd)
		ackPkt.nextNodeHop = nextHopCmd

		nodeDelayCmd := new(commands.NodeDelay)
		nodeDelayCmd.Delay = pkt.nodeDelay.Delay
		ackPkt.cmds = append(ackPkt.cmds, nodeDelayCmd)
		ackPkt.nodeDelay = nodeDelayCmd

		ackPkt.recvAt = pkt.recvAt
		ackPkt.delay = pkt.delay
		ackPkt.mustForward = true

		// XXX: This should probably fudge the delay to account for processing
		// time.

		// Send the SURB-ACK off to the scheduler.
		p.log.Debugf("Handing off user destined SURB-ACK: %v (Src:%v)", ackPkt.id, pkt.id)
		p.s.scheduler.onPacket(ackPkt)
	} else {
		p.log.Debugf("Stored Message: %v (No SURB)", pkt.id)
	}
}

func (p *provider) onAddUser(c *thwack.Conn, l string) error {
	return p.doAddUpdate(c, l, false)
}

func (p *provider) onUpdateUser(c *thwack.Conn, l string) error {
	return p.doAddUpdate(c, l, true)
}

func (p *provider) doAddUpdate(c *thwack.Conn, l string, isUpdate bool) error {
	p.Lock()
	defer p.Unlock()

	sp := strings.Split(l, " ")
	if len(sp) != 3 {
		c.Log().Debugf("[ADD/UPDATE]_USER invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	// Deserialize the public key.
	var pubKey ecdh.PublicKey
	if err := pubKey.UnmarshalText([]byte(sp[2])); err != nil {
		c.Log().Errorf("[ADD/UPDATE]_USER invalid public key: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	// Attempt to add or update the user.
	if err := p.userDB.Add([]byte(sp[1]), &pubKey, isUpdate); err != nil {
		c.Log().Errorf("Failed to add/update user: %v", err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	return c.WriteReply(thwack.StatusOk)
}

func (p *provider) onRemoveUser(c *thwack.Conn, l string) error {
	p.Lock()
	defer p.Unlock()

	sp := strings.Split(l, " ")
	if len(sp) != 2 {
		c.Log().Debugf("REMOVE_USER invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	// Remove the user from the UserDB.
	if err := p.userDB.Remove([]byte(sp[1])); err != nil {
		c.Log().Errorf("Failed to remove user '%v': %v", sp[1], err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	// Remove the user's spool.
	if err := p.spool.Remove([]byte(sp[1])); err != nil {
		// Log an error, but don't return a failed status, because the
		// user has been obliterated from the UserDB at this point.
		c.Log().Errorf("Failed to remove spool '%v': %v", sp[1], err)
	}

	return c.WriteReply(thwack.StatusOk)
}

func newProvider(s *Server) (*provider, error) {
	p := new(provider)
	p.s = s
	p.ch = channels.NewInfiniteChannel()
	p.log = s.logBackend.GetLogger("provider")
	p.haltCh = make(chan interface{})

	var err error
	p.userDB, err = boltuserdb.New(p.s.cfg.Provider.UserDB)
	if err != nil {
		return nil, err
	}

	p.spool, err = boltspool.New(p.s.cfg.Provider.SpoolDB)
	if err != nil {
		p.userDB.Close()
		return nil, err
	}

	// Purge spools that belong to users that no longer exist in the user db.
	if err = p.spool.Vaccum(p.userDB); err != nil {
		p.spool.Close()
		p.userDB.Close()
		return nil, err
	}

	// Wire in the managment related commands.
	if s.cfg.Management.Enable {
		const (
			cmdAddUser    = "ADD_USER"
			cmdUpdateUser = "UPDATE_USER"
			cmdRemoveUser = "REMOVE_USER"
		)

		s.management.RegisterCommand(cmdAddUser, p.onAddUser)
		s.management.RegisterCommand(cmdUpdateUser, p.onUpdateUser)
		s.management.RegisterCommand(cmdRemoveUser, p.onRemoveUser)
	}

	p.Add(1)
	go p.worker()
	return p, nil
}
