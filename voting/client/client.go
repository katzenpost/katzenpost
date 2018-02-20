// client.go - Katzenpost non-voting authority client.
// Copyright (C) 2017, 2018  Yawning Angel, David Stainton
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

// Package client implements the Katzenpost non-voting authority client.
package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	//mrand "math/rand"
	"net"

	"github.com/katzenpost/authority/voting/internal/s11n"
	"github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
	"gopkg.in/op/go-logging.v1"
)

var defaultDialer = &net.Dialer{}

// authorityAuthenticator implements the PeerAuthenticator interface
type authorityAuthenticator struct {
	IdentityPublicKey *eddsa.PublicKey
	LinkPublicKey     *ecdh.PublicKey
	log               *logging.Logger
}

// IsPeerValid authenticates the remote peer's credentials, returning true
// iff the peer is valid.
func (a *authorityAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	if !bytes.Equal(a.IdentityPublicKey.Bytes(), creds.AdditionalData) {
		a.log.Warningf("voting/Client: IsPeerValid(): AD mismatch: %x != %x", a.IdentityPublicKey.Bytes(), creds.AdditionalData[:])
		return false
	}
	if !a.LinkPublicKey.Equal(creds.PublicKey) {
		a.log.Warningf("voting/Client: IsPeerValid(): Link Public Key mismatch: %v != %v", a.LinkPublicKey, creds.PublicKey)
		return false
	}
	return true
}

// Config is a voting authority pki.Client instance.
type Config struct {
	// LogBackend is the `core/log` Backend instance to use for logging.
	LogBackend *log.Backend

	// Authorities is the set of Directory Authority servers.
	Authorities []*config.AuthorityPeer

	// DialContextFn is the optional alternative Dialer.DialContext function
	// to be used when creating outgoing network connections.
	DialContextFn func(ctx context.Context, network, address string) (net.Conn, error)
}

func (cfg *Config) validate() error {
	if cfg.LogBackend == nil {
		return fmt.Errorf("voting/client: LogBackend is mandatory")
	}
	for _, v := range cfg.Authorities {
		err := utils.EnsureAddrIPPort(v.Addresses[0])
		if err != nil {
			return fmt.Errorf("voting/client: Invalid Address: %v", err)
		}
		if v.IdentityPublicKey == nil {
			return fmt.Errorf("voting/client: Identity PublicKey is mandatory")
		}
		if v.LinkPublicKey == nil {
			return fmt.Errorf("voting/client: Link PublicKey is mandatory")
		}
	}
	return nil
}

type connection struct {
	conn    net.Conn
	session *wire.Session
}

type connectionPool struct {
	cfg *Config
	log *logging.Logger
}

func NewConnectionPool(cfg *Config) *connectionPool {
	p := &connectionPool{
		cfg: cfg,
		log: cfg.LogBackend.GetLogger("pki/voting/client/connection_pool"),
	}
	return p
}

func (p *connectionPool) initSession(ctx context.Context, doneCh <-chan interface{}, linkKey *ecdh.PrivateKey, signingKey *eddsa.PublicKey, peer *config.AuthorityPeer) (*connection, error) {
	// Connect to the peer.
	dialFn := p.cfg.DialContextFn
	if dialFn == nil {
		dialFn = defaultDialer.DialContext
	}
	conn, err := dialFn(ctx, "tcp", peer.Addresses[0]) // XXX
	if err != nil {
		return nil, err
	}

	var isOk bool
	defer func() {
		if !isOk {
			conn.Close()
		}
	}()

	var ad []byte
	if signingKey != nil {
		ad = signingKey.Bytes()
	} else {
		p.log.Debug("signingKey is nil")
	}

	peerAuthenticator := &authorityAuthenticator{
		IdentityPublicKey: peer.IdentityPublicKey,
		LinkPublicKey:     peer.LinkPublicKey,
		log:               p.log,
	}

	// Initialize the wire protocol session.
	cfg := &wire.SessionConfig{
		Authenticator:     peerAuthenticator,
		AdditionalData:    ad,
		AuthenticationKey: linkKey,
		RandomReader:      rand.Reader,
	}
	s, err := wire.NewSession(cfg, true)
	if err != nil {
		return nil, err
	}

	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-doneCh:
		}
	}()

	// Handshake.
	if err = s.Initialize(conn); err != nil {
		return nil, err
	}

	isOk = true

	return &connection{
		conn:    conn,
		session: s,
	}, nil
}

func (c *connectionPool) roundTrip(s *wire.Session, cmd commands.Command) (commands.Command, error) {
	if err := s.SendCommand(cmd); err != nil {
		return nil, err
	}
	return s.RecvCommand()
}

func (p *connectionPool) allPeersRoundTrip(ctx context.Context, linkKey *ecdh.PrivateKey, signingKey *eddsa.PublicKey, cmd commands.Command) ([]commands.Command, error) {
	doneCh := make(chan interface{})
	defer close(doneCh)
	responses := []commands.Command{}
	for _, peer := range p.cfg.Authorities {
		conn, err := p.initSession(ctx, doneCh, linkKey, signingKey, peer)
		if err != nil {
			p.log.Noticef("pki/voting/client: failure to connect to Authority peer %s", peer.IdentityPublicKey)
			continue
		}
		resp, err := p.roundTrip(conn.session, cmd)
		if err != nil {
			p.log.Noticef("pki/voting/client: failure in sending command to Authority peer %s: %s", peer, err)
			continue
		}
		responses = append(responses, resp)
	}
	if len(responses) == 0 {
		return nil, errors.New("allPeerRoundTrip failure, got zero responses")
	}
	return responses, nil
}

func (p *connectionPool) randomPeerRoundTrip(ctx context.Context, linkKey *ecdh.PrivateKey, cmd commands.Command) (commands.Command, error) {
	doneCh := make(chan interface{})
	defer close(doneCh)
	//peerIndex := mrand.Intn(len(p.cfg.Authorities) - 1)
	peerIndex := 0

	if len(p.cfg.Authorities) == 0 {
		return nil, errors.New("error: zero Authorities specified in configuration")
	}

	conn, err := p.initSession(ctx, doneCh, linkKey, nil, p.cfg.Authorities[peerIndex])
	if err != nil {
		return nil, err
	}
	resp, err := p.roundTrip(conn.session, cmd)
	return resp, err
}

type client struct {
	cfg  *Config
	log  *logging.Logger
	pool *connectionPool
}

func (c *client) Post(ctx context.Context, epoch uint64, signingKey *eddsa.PrivateKey, d *pki.MixDescriptor) error {
	// Ensure that the descriptor we are about to post is well formed.
	if err := s11n.IsDescriptorWellFormed(d, epoch); err != nil {
		return err
	}
	// Make a serialized + signed + serialized descriptor.
	signed, err := s11n.SignDescriptor(signingKey, d)
	if err != nil {
		return err
	}
	// Convert the link key to an ECDH keypair.
	linkKey := signingKey.ToECDH()
	defer linkKey.Reset()
	// Dispatch the post_descriptor command.
	cmd := &commands.PostDescriptor{
		Epoch:   epoch,
		Payload: []byte(signed),
	}
	responses, err := c.pool.allPeersRoundTrip(ctx, linkKey, signingKey.PublicKey(), cmd)
	if err != nil {
		return err
	}
	// Parse the post_descriptor_status command.
	errs := []error{}
	for _, resp := range responses {
		r, ok := resp.(*commands.PostDescriptorStatus)
		if !ok {
			errs = append(errs, fmt.Errorf("voting/client: Post() unexpected reply: %T", resp))
			continue
		}
		switch r.ErrorCode {
		case commands.DescriptorOk:
		case commands.DescriptorConflict:
			errs = append(errs, pki.ErrInvalidPostEpoch)
		default:
			errs = append(errs, fmt.Errorf("voting/client: Post() rejected by authority: %v", postErrorToString(r.ErrorCode)))
		}
	}
	if len(errs) == 0 {
		return nil
	} else {
		return fmt.Errorf("failure to Post to %d Directory Authorities", len(errs))
	}
	// NOTREACHED
}

func (c *client) Get(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	c.log.Debugf("Get(ctx, %d)", epoch)

	// Generate a random ecdh keypair to use for the link authentication.
	linkKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	defer linkKey.Reset()

	// Initialize the TCP/IP connection, and wire session.
	doneCh := make(chan interface{})
	defer close(doneCh)

	// Dispatch the get_consensus command.
	cmd := &commands.GetConsensus{Epoch: epoch}
	resp, err := c.pool.randomPeerRoundTrip(ctx, linkKey, cmd)
	if err != nil {
		return nil, nil, err
	}

	// Parse the consensus command.
	r, ok := resp.(*commands.Consensus)
	if !ok {
		return nil, nil, fmt.Errorf("voting/client: Get() unexpected reply: %T", resp)
	}
	switch r.ErrorCode {
	case commands.ConsensusOk:
	case commands.ConsensusGone:
		return nil, nil, pki.ErrNoDocument
	default:
		return nil, nil, fmt.Errorf("voting/Client: Get() rejected by authority: %v", getErrorToString(r.ErrorCode))
	}

	// Verify document signatures.
	doc := &pki.Document{}

	sigMap, err := s11n.VerifyPeerMulti(r.Payload, c.cfg.Authorities)
	if err != nil {
		c.log.Errorf("fufu voting/client: Get() invalid consensus document: %s", err)
		return nil, nil, fmt.Errorf("fufu voting/client: Get() invalid consensus document: %s", err)
	}
	if len(sigMap) == len(c.cfg.Authorities) {
		c.log.Notice("OK, received fully signed consensus document.")
	}
	if len(sigMap) <= (len(c.cfg.Authorities)/2 + 1) {
		return nil, nil, fmt.Errorf("voting/client: Get() consensus document not signed by a threshold number of Authorities: %s", err)
	}
	id := new(eddsa.PublicKey)
	for idRaw := range sigMap {
		id.FromBytes(idRaw[:])
		doc, _, err = s11n.VerifyAndParseDocument(r.Payload, id)
		if err != nil {
			return nil, nil, fmt.Errorf("voting/client: Get() impossible signature verification failure: %s", err)
		}
		if doc.Epoch != epoch {
			return nil, nil, errors.New("voting/client: Get() consensus document epoch incorrect.")
		}
		break
	}
	return doc, r.Payload, nil
}

func (c *client) Deserialize(raw []byte) (*pki.Document, error) {
	doc, _, err := s11n.VerifyAndParseDocument(raw, c.cfg.Authorities[0].IdentityPublicKey)
	if err != nil {
		fmt.Errorf("Deserialize failure: %s", err)
	}
	return doc, err
}

// New constructs a new pki.Client instance.
func New(cfg *Config) (pki.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("voting/client: cfg is mandatory")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	c := new(client)
	c.cfg = cfg
	c.log = cfg.LogBackend.GetLogger("pki/voting/client")
	c.pool = NewConnectionPool(cfg)

	return c, nil
}

func getErrorToString(v uint8) string {
	switch v {
	case commands.ConsensusOk:
		return "Ok"
	case commands.ConsensusNotFound:
		return "NotFound"
	case commands.ConsensusGone:
		return "Gone"
	default:
		return fmt.Sprintf("[unknown ErrorCode: %v]", v)
	}
}

func postErrorToString(v uint8) string {
	switch v {
	case commands.DescriptorOk:
		return "Ok"
	case commands.DescriptorInvalid:
		return "Invalid"
	case commands.DescriptorConflict:
		return "Conflict"
	case commands.DescriptorForbidden:
		return "Forbidden"
	default:
		return fmt.Sprintf("[unknown ErrorCode: %v]", v)
	}
}
