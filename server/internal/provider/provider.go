// provider.go - Katzenpost server provider backend.
// Copyright (C) 2017  Yawning Angel and David Stainton
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/monotime"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/config"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	internalConstants "github.com/katzenpost/katzenpost/server/internal/constants"
	"github.com/katzenpost/katzenpost/server/internal/debug"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/katzenpost/katzenpost/server/internal/provider/kaetzchen"
	"github.com/katzenpost/katzenpost/server/internal/sqldb"
	"github.com/katzenpost/katzenpost/server/spool"
	"github.com/katzenpost/katzenpost/server/spool/boltspool"
	"github.com/katzenpost/katzenpost/server/userdb"
	"github.com/katzenpost/katzenpost/server/userdb/boltuserdb"
	"github.com/katzenpost/katzenpost/server/userdb/externuserdb"
	"github.com/prometheus/client_golang/prometheus"
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

	kaetzchenWorker           *kaetzchen.KaetzchenWorker
	cborPluginKaetzchenWorker *kaetzchen.CBORPluginWorker
}

var (
	packetsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: internalConstants.Namespace,
			Name:      "dropped_packets_total",
			Subsystem: internalConstants.ProviderSubsystem,
			Help:      "Number of dropped packets",
		},
	)
)

func init() {
	prometheus.MustRegister(packetsDropped)
}

func (p *provider) Halt() {
	p.Worker.Halt()

	p.ch.Close()
	p.kaetzchenWorker.Halt()
	p.cborPluginKaetzchenWorker.Halt()
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

func (p *provider) Spool() spool.Spool {
	return p.spool
}

func (p *provider) UserDB() userdb.UserDB {
	return p.userDB
}

func (p *provider) AuthenticateClient(c *wire.PeerCredentials) bool {
	ad, err := p.fixupUserNameCase(c.AdditionalData)
	if err != nil {
		return false
	}
	isValid := p.userDB.IsValid(ad, c.PublicKey)
	if !isValid {
		if len(c.AdditionalData) == sConstants.NodeIDLength {
			p.log.Errorf("Authentication failed: User: '%v', Key: '%v' (Probably a peer)", debug.BytesToPrintString(c.AdditionalData), c.PublicKey)
		} else {
			p.log.Errorf("Authentication failed: User: '%v', Key: '%v'", utils.ASCIIBytesToPrintString(c.AdditionalData), c.PublicKey)
		}
	}
	return isValid
}

func (p *provider) OnPacket(pkt *packet.Packet) {
	p.ch.In() <- pkt
}

func (p *provider) KaetzchenForPKI() (map[string]map[string]interface{}, error) {
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

func (p *provider) connectedClients() (map[[sConstants.RecipientIDLength]byte]interface{}, error) {
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

func (p *provider) gcEphemeralClients() {
	p.log.Debug("garbage collecting expired ephemeral clients")
	connectedClients, err := p.connectedClients()
	if err != nil {
		p.log.Errorf("wtf: %s", err)
		return
	}
	err = p.Spool().VacuumExpired(p.UserDB(), connectedClients)
	if err != nil {
		p.log.Errorf("wtf: %s", err)
		return
	}
}

func (p *provider) worker() {

	maxDwell := time.Duration(p.glue.Config().Debug.ProviderDelay) * time.Millisecond

	defer p.log.Debugf("Halting Provider worker.")

	ch := p.ch.Out()

	// Here we optionally set this GC timer. If unset the
	// channel remains nil and has no effect on the select
	// statement below. If set then the timer will periodically
	// write to the channel triggering our GC routine.
	var gcEphemeralClientGCTickerChan <-chan time.Time
	if p.glue.Config().Provider.EnableEphemeralClients {
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

			if dwellTime := monotime.Now() - pkt.DispatchAt; dwellTime > maxDwell {
				p.log.Debugf("Dropping packet: %v (Spend %v in queue)", pkt.ID, dwellTime)
				packetsDropped.Inc()
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
				packetsDropped.Inc()
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
				packetsDropped.Inc()
				pkt.Dispose()
			} else {
				// Note that we pass ownership of pkt to p.kaetzchenWorker
				// which will take care to dispose of it.
				p.cborPluginKaetzchenWorker.OnKaetzchen(pkt)
			}
			continue
		}

		// Post-process the recipient.
		recipient, err := p.fixupRecipient(pkt.Recipient.ID[:])
		if err != nil {
			p.log.Debugf("Dropping packet: %v (Invalid Recipient: '%v')", pkt.ID, utils.ASCIIBytesToPrintString(recipient))
			packetsDropped.Inc()
			pkt.Dispose()
			continue
		}

		// Ensure the packet is for a valid recipient.
		if !p.userDB.Exists(recipient) {
			p.log.Debugf("Dropping packet: %v (Invalid Recipient: '%v')", pkt.ID, utils.ASCIIBytesToPrintString(recipient))
			packetsDropped.Inc()
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
	geo := sphinx.DefaultGeometry()
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

func (p *provider) onToUser(pkt *packet.Packet, recipient []byte) {
	ct, surb, err := packet.ParseForwardPacket(pkt)
	if err != nil {
		p.log.Debugf("Dropping packet: %v (%v)", pkt.ID, err)
		packetsDropped.Inc()
		return
	}

	// Store the ciphertext in the spool.
	if err := p.spool.StoreMessage(recipient, ct); err != nil {
		p.log.Debugf("Failed to store message payload: %v (%v)", pkt.ID, err)
		return
	}

	// Iff there is a SURB, generate a SURB-ACK and schedule.
	if surb != nil {
		ackPkt, err := packet.NewPacketFromSURB(pkt, surb, nil)
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
	pubKey, err := wire.DefaultScheme.UnmarshalTextPublicKey([]byte(sp[2]))
	if err != nil {
		c.Log().Errorf("[ADD/UPDATE]_USER invalid public key: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	// Attempt to add or update the user.
	u, err := p.fixupUserNameCase([]byte(sp[1]))
	if err != nil {
		c.Log().Errorf("[ADD/UPDATE]_USER invalid user: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}
	if err = p.userDB.Add(u, pubKey, isUpdate); err != nil {
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

func (p *provider) onRemoveUserIdentity(c *thwack.Conn, l string) error {
	p.Lock()
	defer p.Unlock()

	sp := strings.Split(l, " ")
	switch len(sp) {
	case 2:
	default:
		c.Log().Debugf("REMOVE_USER_IDENTITY invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	u, err := p.fixupUserNameCase([]byte(sp[1]))
	if err != nil {
		c.Log().Errorf("REMOVE_USER_IDENTITY invalid user: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	if err = p.userDB.SetIdentity(u, nil); err != nil {
		c.Log().Errorf("Failed to set identity for user '%v': %v", u, err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	return c.WriteReply(thwack.StatusOk)
}

func (p *provider) onSetUserIdentity(c *thwack.Conn, l string) error {
	p.Lock()
	defer p.Unlock()

	var err error
	var pubKey wire.PublicKey

	sp := strings.Split(l, " ")
	switch len(sp) {
	case 2:
	case 3:
		pubKey, err = wire.DefaultScheme.UnmarshalTextPublicKey([]byte(sp[2]))
		if err != nil {
			c.Log().Errorf("SET_USER_IDENTITY invalid public key: %v", err)
			return c.WriteReply(thwack.StatusSyntaxError)
		}
	default:
		c.Log().Debugf("SET_USER_IDENTITY invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	u, err := p.fixupUserNameCase([]byte(sp[1]))
	if err != nil {
		c.Log().Errorf("SET_USER_IDENTITY invalid user: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	if err = p.userDB.SetIdentity(u, pubKey); err != nil {
		c.Log().Errorf("Failed to set identity for user '%v': %v", u, err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	return c.WriteReply(thwack.StatusOk)
}

func (p *provider) onUserLink(c *thwack.Conn, l string) error {
	p.Lock()
	defer p.Unlock()

	sp := strings.Split(l, " ")
	if len(sp) != 2 {
		c.Log().Debugf("USER_LINK invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	u, err := p.fixupUserNameCase([]byte(sp[1]))
	if err != nil {
		c.Log().Errorf("USER_LINK invalid user: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	pubKey, err := p.userDB.Link(u)
	if err != nil {
		c.Log().Errorf("Failed to query link key for user '%s': %v", string(u), err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	return c.Writer().PrintfLine("%v %v", thwack.StatusOk, pubKey)
}

func (p *provider) onUserIdentity(c *thwack.Conn, l string) error {
	p.Lock()
	defer p.Unlock()

	sp := strings.Split(l, " ")
	if len(sp) != 2 {
		c.Log().Debugf("USER_IDENTITY invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	u, err := p.fixupUserNameCase([]byte(sp[1]))
	if err != nil {
		c.Log().Errorf("USER_IDENTITY invalid user: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	pubKey, err := p.userDB.Identity(u)
	if err != nil {
		c.Log().Errorf("Failed to query identity for user '%v': %v", u, err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	return c.Writer().PrintfLine("%v %v", thwack.StatusOk, pubKey)
}

func (p *provider) onSendRate(c *thwack.Conn, l string) error {
	p.Lock()
	defer p.Unlock()

	sp := strings.Split(l, " ")
	if len(sp) != 2 {
		c.Log().Debugf("SEND_RATE invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	rate, err := strconv.ParseUint(sp[1], 10, 64)
	if err != nil {
		c.Log().Errorf("SEND_RATE invalid duration: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	for _, l := range p.glue.Listeners() {
		l.OnNewSendRatePerMinute(rate)
	}

	return c.Writer().PrintfLine("%v %v", thwack.StatusOk, rate)
}

func (p *provider) onSendBurst(c *thwack.Conn, l string) error {
	p.Lock()
	defer p.Unlock()

	sp := strings.Split(l, " ")
	if len(sp) != 2 {
		c.Log().Debugf("SEND_BURST invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	burst, err := strconv.ParseUint(sp[1], 10, 64)
	if err != nil {
		c.Log().Errorf("SEND_BURST invalid integer: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	for _, l := range p.glue.Listeners() {
		l.OnNewSendBurst(burst)
	}

	return c.Writer().PrintfLine("%v %v", thwack.StatusOk, burst)
}

// New constructs a new provider instance.
func New(glue glue.Glue) (glue.Provider, error) {
	kaetzchenWorker, err := kaetzchen.New(glue)
	if err != nil {
		return nil, err
	}
	cborPluginWorker, err := kaetzchen.NewCBORPluginWorker(glue)
	if err != nil {
		return nil, err
	}
	p := &provider{
		glue:                      glue,
		log:                       glue.LogBackend().GetLogger("provider"),
		ch:                        channels.NewInfiniteChannel(),
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
		if cfg.Provider.TrustOnFirstUse {
			p.userDB, err = boltuserdb.New(cfg.Provider.UserDB.Bolt.UserDB, boltuserdb.WithTrustOnFirstUse())
		} else {
			p.userDB, err = boltuserdb.New(cfg.Provider.UserDB.Bolt.UserDB)
		}
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
	if err = p.spool.Vacuum(p.userDB); err != nil {
		return nil, err
	}

	// Wire in the management related commands.
	if cfg.Management.Enable {
		const (
			cmdAddUser            = "ADD_USER"
			cmdUpdateUser         = "UPDATE_USER"
			cmdRemoveUser         = "REMOVE_USER"
			cmdSetUserIdentity    = "SET_USER_IDENTITY"
			cmdRemoveUserIdentity = "REMOVE_USER_IDENTITY"
			cmdUserIdentity       = "USER_IDENTITY"
			cmdUserLink           = "USER_LINK"
			cmdSendRate           = "SEND_RATE"
			cmdSendBurst          = "SEND_BURST"
		)

		glue.Management().RegisterCommand(cmdAddUser, p.onAddUser)
		glue.Management().RegisterCommand(cmdUpdateUser, p.onUpdateUser)
		glue.Management().RegisterCommand(cmdRemoveUser, p.onRemoveUser)
		glue.Management().RegisterCommand(cmdSetUserIdentity, p.onSetUserIdentity)
		glue.Management().RegisterCommand(cmdRemoveUserIdentity, p.onRemoveUserIdentity)
		glue.Management().RegisterCommand(cmdUserIdentity, p.onUserIdentity)
		glue.Management().RegisterCommand(cmdUserLink, p.onUserLink)
		glue.Management().RegisterCommand(cmdSendRate, p.onSendRate)
		glue.Management().RegisterCommand(cmdSendBurst, p.onSendBurst)
	}

	// Start the workers.
	for i := 0; i < cfg.Debug.NumProviderWorkers; i++ {
		p.Go(p.worker)
	}

	isOk = true
	return p, nil
}
