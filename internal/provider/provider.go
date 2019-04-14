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
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/sphinx"
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
	"github.com/katzenpost/server/registration"
	"github.com/katzenpost/server/spool"
	"github.com/katzenpost/server/spool/boltspool"
	"github.com/katzenpost/server/userdb"
	"github.com/katzenpost/server/userdb/boltuserdb"
	"github.com/katzenpost/server/userdb/externuserdb"
	"golang.org/x/text/secure/precis"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

type registerIdentityRequest struct {
	User              string
	IdentityPublicKey string
}

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

	httpServers []*http.Server
}

func (p *provider) Halt() {
	p.stopUserRegistrationHTTP()
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
	if map1 == nil && map2 != nil {
		return map2, nil
	}
	if map1 != nil && map2 == nil {
		return map1, nil
	}
	// merge sets, panic on duplicate
	for k, v := range map2 {
		_, ok := map1[k]
		if ok {
			p.log.Debug("WARNING: duplicate plugin entries")
			panic("WARNING: duplicate plugin entries")
		}
		map1[k] = v
	}
	return map1, nil
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
		if p.kaetzchenWorker.IsKaetzchen(pkt.Recipient.ID) {
			// Packet is destined for a Kaetzchen auto-responder agent, and
			// can't be a SURB-Reply.
			if pkt.IsSURBReply() {
				p.log.Debugf("Dropping packet: %v (SURB-Reply for Kaetzchen)", pkt.ID)
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
	ct, surb, err := packet.ParseForwardPacket(pkt)
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

	var pubKey *ecdh.PublicKey

	sp := strings.Split(l, " ")
	switch len(sp) {
	case 2:
	case 3:
		pubKey = new(ecdh.PublicKey)
		if err := pubKey.FromString(sp[2]); err != nil {
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

func (p *provider) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !p.validateRequest(response, request) {
		return
	}
	requestUser := request.FormValue(registration.UserField)
	if len(requestUser) == 0 {
		p.log.Error("Provider ServeHTTP register zero user error")
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	user, err := p.fixupUserNameCase([]byte(requestUser))
	if err != nil {
		p.log.Error("Provider ServeHTTP register fixupUserNameCase failure")
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	command := request.FormValue(registration.CommandField)
	switch command {
	case registration.RegisterLinkCommand:
		p.processLinkRegistration(user, response, request)
		return
	case registration.RegisterLinkAndIdentityCommand:
		p.processIdentityRegistration(user, response, request)
		return
	default:
		p.log.Error("Provider ServeHTTP invalid registration type error")
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	// NOT reached
}

func (p *provider) validateRequest(response http.ResponseWriter, request *http.Request) bool {
	if request.URL.Path != registration.URLBase {
		p.log.Error("Provider ServeHTTP incorrect url error")
		response.WriteHeader(http.StatusNotFound)
		return false
	}
	if request.Method != http.MethodPost {
		p.log.Error("Provider ServeHTTP incorrect method error")
		response.WriteHeader(http.StatusInternalServerError)
		return false
	}
	command := request.FormValue(registration.CommandField)
	if len(command) == 0 {
		p.log.Error("Provider ServeHTTP zero reg type error")
		response.WriteHeader(http.StatusInternalServerError)
		return false
	}
	version := request.FormValue(registration.VersionField)
	if len(version) == 0 || version != registration.Version {
		p.log.Error("Provider ServeHTTP register version mismatch error")
		response.WriteHeader(http.StatusInternalServerError)
		return false
	}
	return true
}

func (p *provider) processLinkRegistration(user []byte, response http.ResponseWriter, request *http.Request) {
	requestKey := request.FormValue(registration.LinkKeyField)
	if len(requestKey) == 0 {
		p.log.Error("Provider ServeHTTP register zero key error")
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	pubKey := new(ecdh.PublicKey)
	if err := pubKey.FromString(requestKey); err != nil {
		p.log.Errorf("Provider ServeHTTP pub key from string error: %s", err)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := p.userDB.Add(user, pubKey, false); err != nil {
		p.log.Errorf("Provider ServeHTTP user Add error: %s", err)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	p.log.Noticef("HTTP Registration created user with link key: %s", user)

	// Send a response back to the client.
	message := "OK\n"
	response.Write([]byte(message))
}

func (p *provider) processIdentityRegistration(user []byte, response http.ResponseWriter, request *http.Request) {
	key, err := p.userDB.Identity(user)
	if key != nil {
		p.log.Errorf("Provider ServeHTTP Identity error")
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	// link key
	rawLinkKey := request.FormValue(registration.LinkKeyField)
	if len(rawLinkKey) == 0 {
		p.log.Error("Provider ServeHTTP register zero key error")
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	linkKey := new(ecdh.PublicKey)
	if err := linkKey.FromString(rawLinkKey); err != nil {
		p.log.Errorf("Provider ServeHTTP pub key from string error: %s", err)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := p.userDB.Add(user, linkKey, false); err != nil {
		p.log.Errorf("Provider ServeHTTP user Add error: %s", err)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	// identity key
	rawIdentityKey := request.FormValue(registration.IdentityKeyField)
	if len(rawIdentityKey) == 0 {
		p.log.Error("Provider ServeHTTP zero id key error")
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	identityKey := new(ecdh.PublicKey)
	if err := identityKey.FromString(rawIdentityKey); err != nil {
		p.log.Errorf("Provider ServeHTTP id key from string error: %s", err)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err = p.userDB.SetIdentity(user, identityKey); err != nil {
		p.log.Errorf("Provider ServeHTTP SetIdentity error: %s", err)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	p.log.Noticef("HTTP Registration created user with link and identity keys: %s", user)

	// Send a response back to the client.
	message := "OK\n"
	response.Write([]byte(message))
}

func (p *provider) stopUserRegistrationHTTP() {
	if !p.glue.Config().Provider.EnableUserRegistrationHTTP {
		return
	}
	p.log.Info("Stopping User Registration HTTP listener(s).")
	for _, s := range p.httpServers {
		if err := s.Shutdown(context.Background()); err != nil {
			p.log.Errorf("HTTP server Shutdown error: %v", err)
		}
	}
}

func (p *provider) initUserRegistrationHTTP() {
	p.log.Info("Starting User Registration HTTP listener(s).")
	p.httpServers = make([]*http.Server, len(p.glue.Config().Provider.UserRegistrationHTTPAddresses))
	for i, addr := range p.glue.Config().Provider.UserRegistrationHTTPAddresses {
		s := &http.Server{
			Addr:     addr,
			Handler:  p,
			ErrorLog: p.glue.LogBackend().GetGoLogger("user_registration_http", "info"),
		}
		p.httpServers[i] = s
		go func() {
			if err := s.ListenAndServe(); err != http.ErrServerClosed {
				// Error starting or closing listener:
				p.log.Errorf("HTTP server ListenAndServe: %v", err)
			}
		}()
	}
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

	// Start the User Registration HTTP service listener(s).
	if cfg.Provider.EnableUserRegistrationHTTP {
		p.initUserRegistrationHTTP()
	}

	// Start the workers.
	for i := 0; i < cfg.Debug.NumProviderWorkers; i++ {
		p.Go(p.worker)
	}

	isOk = true
	return p, nil
}
