// provider.go - Katzenpost server provider backend.
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

// Package provider implements the Katzenpost sever provider.
package provider

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/sphinx/commands"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/thwack"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/config"
	"github.com/katzenpost/server/internal/debug"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/internal/packet"
	"github.com/katzenpost/server/internal/provider/kaetzchen"
	"github.com/katzenpost/server/internal/sqldb"
	"github.com/katzenpost/server/spool"
	"github.com/katzenpost/server/spool/boltspool"
	"github.com/katzenpost/server/userdb"
	"github.com/katzenpost/server/userdb/boltuserdb"
	"github.com/katzenpost/server/userdb/externuserdb"
	"golang.org/x/text/secure/precis"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

type provider struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	ch     *channels.InfiniteChannel
	sqlDB  *sqldb.SQLDB
	userDB userdb.UserDB
	spool  spool.Spool

	kaetzchen map[[sConstants.RecipientIDLength]byte]kaetzchen.Kaetzchen
}

func (p *provider) Halt() {
	p.Worker.Halt()

	p.ch.Close()
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
	for k, v := range p.kaetzchen {
		v.Halt()
		delete(p.kaetzchen, k)
	}
}

func (p *provider) Spool() spool.Spool {
	return p.spool
}

func (p *provider) AuthenticateClient(c *wire.PeerCredentials) bool {
	ad, err := p.fixupUserNameCase(c.AdditionalData)
	if err != nil {
		return false
	}
	isValid := p.userDB.IsValid(ad, c.PublicKey)
	if !isValid {
		if len(c.AdditionalData) == sConstants.NodeIDLength {
			p.log.Errorf("Authenticate failed: User: '%v', Key: '%v' (Probably a peer)", debug.BytesToPrintString(c.AdditionalData), c.PublicKey)
		} else {
			p.log.Errorf("Authenticate failed: User: '%v', Key: '%v'", utils.ASCIIBytesToPrintString(c.AdditionalData), c.PublicKey)
		}
	}
	return isValid
}

func (p *provider) OnPacket(pkt *packet.Packet) {
	p.ch.In() <- pkt
}

func (p *provider) KaetzchenForPKI() map[string]map[string]interface{} {
	if len(p.kaetzchen) == 0 {
		return nil
	}

	m := make(map[string]map[string]interface{})
	for _, v := range p.kaetzchen {
		m[v.Capability()] = v.Parameters()
	}
	return m
}

func (p *provider) fixupUserNameCase(user []byte) ([]byte, error) {
	// Unless explicitly specified otherwise, force usernames to lower case.
	if p.glue.Config().Provider.BinaryRecipients {
		return user, nil
	}

	if p.glue.Config().Provider.CaseSensitiveRecipients {
		return precis.UsernameCasePreserved.Bytes(user)
	}
	return precis.UsernameCaseMapped.Bytes(user)
}

func (p *provider) fixupRecipient(recipient []byte) ([]byte, error) {
	// If the provider is configured for binary recipients, do no post
	// processing.
	if p.glue.Config().Provider.BinaryRecipients {
		return recipient, nil
	}

	// Fix the recipient by trimming off the trailing NUL bytes.
	b := bytes.TrimRight(recipient, "\x00")

	// (Optional, Default) Force recipients to lower case.
	var err error
	b, err = p.fixupUserNameCase(b)
	if err != nil {
		return nil, err
	}

	// (Optional) Discard everything after the first recipient delimiter...
	if delimiter := p.glue.Config().Provider.RecipientDelimiter; delimiter != "" {
		if sp := bytes.SplitN(b, []byte(delimiter), 2); sp != nil {
			// ... As long as the recipient doesn't start with a delimiter.
			if len(sp[0]) > 0 {
				b = sp[0]
			}
		}
	}

	return b, nil
}

func (p *provider) worker() {
	maxDwell := time.Duration(p.glue.Config().Debug.ProviderDelay) * time.Millisecond

	defer p.log.Debugf("Halting Provider worker.")

	ch := p.ch.Out()

	for {
		var pkt *packet.Packet
		select {
		case <-p.HaltCh():
			p.log.Debugf("Terminating gracefully.")
			return
		case e := <-ch:
			pkt = e.(*packet.Packet)
			if dwellTime := monotime.Now() - pkt.DispatchAt; dwellTime > maxDwell {
				p.log.Debugf("Dropping packet: %v (Spend %v in queue)", pkt.ID, dwellTime)
				pkt.Dispose()
				continue
			}
		}

		// Kaetzchen endpoints are published in the PKI and are never
		// user-facing, so omit the recipient-post processing.  If clients
		// are written under the assumption that Kaetzchen addresses are
		// normalized, that's their problem.
		if dstKaetzchen := p.kaetzchen[pkt.Recipient.ID]; dstKaetzchen != nil {
			// Packet is destined for a Kaetzchen auto-responder agent, and
			// can't be a SURB-Reply.
			if pkt.IsSURBReply() {
				p.log.Debugf("Dropping packet: %v (SURB-Reply for Kaetzchen)", pkt.ID)
			} else {
				p.onToKaetzchen(pkt, dstKaetzchen)
			}
			pkt.Dispose()
			continue
		}

		// Post-process the recipient.
		recipient, err := p.fixupRecipient(pkt.Recipient.ID[:])
		if err != nil {
			p.log.Debugf("Dropping packet: %v (Invalid Recipient: '%v')", pkt.ID, utils.ASCIIBytesToPrintString(recipient))
			pkt.Dispose()
			continue
		}

		// Ensure the packet is for a valid recipient.
		if !p.userDB.Exists(recipient) {
			p.log.Debugf("Dropping packet: %v (Invalid Recipient: '%v')", pkt.ID, utils.ASCIIBytesToPrintString(recipient))
			pkt.Dispose()
			continue
		}

		// Process the packet based on type.
		if pkt.IsSURBReply() {
			p.onSURBReply(pkt, recipient)
		} else {
			// Caller checks that the packet is either a SURB-Reply or a user
			// message, so this must be the latter.
			p.onToUser(pkt, recipient)
		}

		pkt.Dispose()
	}
}

func (p *provider) onSURBReply(pkt *packet.Packet, recipient []byte) {
	if len(pkt.Payload) != sphinx.PayloadTagLength+constants.ForwardPayloadLength {
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

func (p *provider) onToUser(pkt *packet.Packet, recipient []byte) {
	ct, surb, err := parseForwardPacket(pkt)
	if err != nil {
		p.log.Debugf("Dropping packet: %v (%v)", pkt.ID, err)
		return
	}

	// Store the ciphertext in the spool.
	if err := p.spool.StoreMessage(recipient, ct); err != nil {
		p.log.Debugf("Failed to store message payload: %v (%v)", pkt.ID, err)
		return
	}

	// Iff there is a SURB, generate a SURB-ACK and schedule.
	if surb != nil {
		ackPkt, err := newPacketFromSURB(pkt, surb, nil)
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

func (p *provider) onToKaetzchen(pkt *packet.Packet, dst kaetzchen.Kaetzchen) {
	ct, surb, err := parseForwardPacket(pkt)
	if err != nil {
		p.log.Debugf("Dropping Kaetzchen request: %v (%v)", pkt.ID, err)
		return
	}

	// Dispatch the packet to the agent.
	resp, err := dst.OnRequest(pkt.ID, ct, surb != nil)
	switch {
	case err == nil:
	case err == kaetzchen.ErrNoResponse:
		p.log.Debugf("Processed Kaetzchen request: %v (No response)", pkt.ID)
		return
	default:
		p.log.Debugf("Failed to handle Kaetzchen request: %v (%v)", pkt.ID, err)
		return
	}

	// Iff there is a SURB, generate a SURB-Reply and schedule.
	if surb != nil {
		// Prepend the response header.
		resp = append([]byte{0x01, 0x00}, resp...)

		respPkt, err := newPacketFromSURB(pkt, surb, resp)
		if err != nil {
			p.log.Debugf("Failed to generate SURB-Reply: %v (%v)", pkt.ID, err)
			return
		}

		p.log.Debugf("Handing off newly generated SURB-Reply: %v (Src:%v)", respPkt.ID, pkt.ID)
		p.glue.Scheduler().OnPacket(respPkt)
	} else if resp != nil {
		// This is silly and I'm not sure why anyone will do this, but
		// there's nothing that can be done at this point, the Kaetzchen
		// implementation should have caught this.
		p.log.Debugf("Kaetzchen message: %v (Has reply but no SURB)", pkt.ID)
	}
}

func (p *provider) registerKaetzchen(k kaetzchen.Kaetzchen) error {
	capa := k.Capability()

	params := k.Parameters()
	if params == nil {
		return fmt.Errorf("provider: Kaetzchen: '%v' provided no parameters", capa)
	}

	// Sanitize the endpoint.
	var ep string
	if v, ok := params[kaetzchen.ParameterEndpoint]; !ok {
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
	if _, ok := p.kaetzchen[epKey]; ok {
		return fmt.Errorf("provider: Kaetzchen: '%v' endpoint '%v' already registered", capa, ep)
	}
	p.kaetzchen[epKey] = k
	p.log.Noticef("Registered Kaetzchen: '%v' -> '%v'.", ep, capa)

	return nil
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
	if err := pubKey.FromString(sp[2]); err != nil {
		c.Log().Errorf("[ADD/UPDATE]_USER invalid public key: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	// Attempt to add or update the user.
	u, err := p.fixupUserNameCase([]byte(sp[1]))
	if err != nil {
		c.Log().Errorf("[ADD/UPDATE]_USER invalid user: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}
	if err = p.userDB.Add(u, &pubKey, isUpdate); err != nil {
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

	u, err := p.fixupUserNameCase([]byte(sp[1]))
	if err != nil {
		c.Log().Errorf("REMOVE_USER invalid user: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	// Remove the user from the UserDB.
	if err = p.userDB.Remove(u); err != nil {
		c.Log().Errorf("Failed to remove user '%v': %v", u, err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	// Remove the user's spool.
	if err = p.spool.Remove(u); err != nil {
		// Log an error, but don't return a failed status, because the
		// user has been obliterated from the UserDB at this point.
		c.Log().Errorf("Failed to remove spool '%v': %v", u, err)
	}

	return c.WriteReply(thwack.StatusOk)
}

func parseForwardPacket(pkt *packet.Packet) ([]byte, []byte, error) {
	const (
		hdrLength    = constants.SphinxPlaintextHeaderLength + sphinx.SURBLength
		flagsPadding = 0
		flagsSURB    = 1
		reserved     = 0
	)

	// Sanity check the forward packet payload length.
	if len(pkt.Payload) != constants.ForwardPayloadLength {
		return nil, nil, fmt.Errorf("invalid payload length: %v", len(pkt.Payload))
	}

	// Parse the payload, which should be a valid BlockSphinxPlaintext.
	b := pkt.Payload
	if len(b) < hdrLength {
		return nil, nil, fmt.Errorf("truncated message block")
	}
	if b[1] != reserved {
		return nil, nil, fmt.Errorf("invalid message reserved: 0x%02x", b[1])
	}
	ct := b[hdrLength:]
	var surb []byte
	switch b[0] {
	case flagsPadding:
	case flagsSURB:
		surb = b[constants.SphinxPlaintextHeaderLength:hdrLength]
	default:
		return nil, nil, fmt.Errorf("invalid message flags: 0x%02x", b[0])
	}
	if len(ct) != constants.UserForwardPayloadLength {
		return nil, nil, fmt.Errorf("mis-sized user payload: %v", len(ct))
	}

	return ct, surb, nil
}

func newPacketFromSURB(pkt *packet.Packet, surb, payload []byte) (*packet.Packet, error) {
	if !pkt.IsToUser() {
		return nil, fmt.Errorf("invalid commands to generate a SURB reply")
	}

	// Pad out payloads to the full packet size.
	var respPayload [constants.ForwardPayloadLength]byte
	switch {
	case len(payload) == 0:
	case len(payload) > constants.ForwardPayloadLength:
		return nil, fmt.Errorf("oversized response payload: %v", len(payload))
	default:
		copy(respPayload[:], payload)
	}

	// Build a response packet using a SURB.
	//
	// TODO/perf: This is a crypto operation that is paralleizable, and
	// could be handled by the crypto worker(s), since those are allocated
	// based on hardware acceleration considerations.  However the forward
	// packet processing doesn't constantly utilize the AES-NI units due
	// to the non-AEZ components of a Sphinx Unwrap operation.
	rawRespPkt, firstHop, err := sphinx.NewPacketFromSURB(surb, respPayload[:])
	if err != nil {
		return nil, err
	}

	// Build the command vector for the SURB-ACK
	cmds := make([]commands.RoutingCommand, 0, 2)

	nextHopCmd := new(commands.NextNodeHop)
	copy(nextHopCmd.ID[:], firstHop[:])
	cmds = append(cmds, nextHopCmd)

	nodeDelayCmd := new(commands.NodeDelay)
	nodeDelayCmd.Delay = pkt.NodeDelay.Delay
	cmds = append(cmds, nodeDelayCmd)

	// Assemble the response packet.
	respPkt, _ := packet.New(rawRespPkt)
	respPkt.Set(nil, cmds)

	respPkt.RecvAt = pkt.RecvAt
	respPkt.Delay = pkt.Delay
	respPkt.MustForward = true

	// XXX: This should probably fudge the delay to account for processing
	// time.

	return respPkt, nil
}

// New constructs a new provider instance.
func New(glue glue.Glue) (glue.Provider, error) {
	p := &provider{
		glue:      glue,
		log:       glue.LogBackend().GetLogger("provider"),
		ch:        channels.NewInfiniteChannel(),
		kaetzchen: make(map[[sConstants.RecipientIDLength]byte]kaetzchen.Kaetzchen),
	}

	cfg := glue.Config()

	isOk := false
	defer func() {
		if !isOk {
			p.Halt()
		}
	}()

	var err error
	if cfg.Provider.SQLDB != nil {
		if cfg.Provider.UserDB.Backend == config.BackendSQL || cfg.Provider.SpoolDB.Backend == config.BackendSQL {
			p.sqlDB, err = sqldb.New(glue)
			if err != nil {
				return nil, err
			}
		} else {
			p.log.Warningf("SQL database configured but not used for the User or Spool databases.")
		}
	}

	switch cfg.Provider.UserDB.Backend {
	case config.BackendBolt:
		p.userDB, err = boltuserdb.New(cfg.Provider.UserDB.Bolt.UserDB)
	case config.BackendExtern:
		p.userDB, err = externuserdb.New(cfg.Provider.UserDB.Extern.ProviderURL)
	case config.BackendSQL:
		if p.sqlDB != nil {
			p.userDB, err = p.sqlDB.UserDB()
		} else {
			err = errors.New("provider: SQL UserDB backend with no SQL database")
		}
	default:
		return nil, fmt.Errorf("provider: Unknown UserDB backend: %v", cfg.Provider.UserDB.Backend)
	}
	if err != nil {
		return nil, err
	}

	switch cfg.Provider.SpoolDB.Backend {
	case config.BackendBolt:
		p.spool, err = boltspool.New(cfg.Provider.SpoolDB.Bolt.SpoolDB)
	case config.BackendSQL:
		if p.sqlDB != nil {
			p.spool = p.sqlDB.Spool()
		} else {
			err = errors.New("provider: SQL SpoolDB backend with no SQL database")
		}
	default:
		err = fmt.Errorf("provider: Unknown SpoolDB backend: %v", cfg.Provider.SpoolDB.Backend)
	}
	if err != nil {
		return nil, err
	}

	// Purge spools that belong to users that no longer exist in the user db.
	if err = p.spool.Vaccum(p.userDB); err != nil {
		return nil, err
	}

	// Wire in the managment related commands.
	if cfg.Management.Enable {
		const (
			cmdAddUser    = "ADD_USER"
			cmdUpdateUser = "UPDATE_USER"
			cmdRemoveUser = "REMOVE_USER"
		)

		glue.Management().RegisterCommand(cmdAddUser, p.onAddUser)
		glue.Management().RegisterCommand(cmdUpdateUser, p.onUpdateUser)
		glue.Management().RegisterCommand(cmdRemoveUser, p.onRemoveUser)
	}

	// Initialize the Kaetzchen.
	capaMap := make(map[string]bool)
	for _, v := range glue.Config().Provider.Kaetzchen {
		capa := v.Capability
		if v.Disable {
			p.log.Noticef("Skipping disabled Kaetzchen: '%v'.", capa)
			continue
		}

		ctor, ok := kaetzchen.BuiltInCtors[capa]
		if !ok {
			return nil, fmt.Errorf("provider: Kaetzchen: Unsupported capability: '%v'", capa)
		}

		k, err := ctor(v, glue)
		if err != nil {
			return nil, err
		}
		if err = p.registerKaetzchen(k); err != nil {
			return nil, err
		}

		if capaMap[capa] {
			return nil, fmt.Errorf("provider: Kaetzchen '%v' registered more than once", capa)
		}
		capaMap[capa] = true
	}

	// Start the workers.
	for i := 0; i < cfg.Debug.NumProviderWorkers; i++ {
		p.Go(p.worker)
	}

	isOk = true
	return p, nil
}
