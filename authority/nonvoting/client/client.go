// client.go - Katzenpost non-voting authority client.
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

// Package client implements the Katzenpost non-voting authority client.
package client

import (
	"context"
	"crypto/hmac"
	"fmt"
	"net"

	"github.com/katzenpost/katzenpost/authority/internal/s11n"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"gopkg.in/op/go-logging.v1"
)

var defaultDialer = &net.Dialer{}

// Config is a nonvoting authority pki.Client instance.
type Config struct {

	// LogBackend is the `core/log` Backend instance to use for logging.
	LogBackend *log.Backend

	// Address is the authority's address to connect to for posting and
	// fetching documents.
	Address string

	// PublicKey is the authority's public key to use when validating documents.
	AuthorityIdentityKey sign.PublicKey

	// AuthorityLinkKey is the authority's link key used in our noise wire protocol.
	AuthorityLinkKey wire.PublicKey

	// LinkKey is the client's link layer keypair.
	LinkKey wire.PrivateKey

	// DialContextFn is the optional alternative Dialer.DialContext function
	// to be used when creating outgoing network connections.
	DialContextFn func(ctx context.Context, network, address string) (net.Conn, error)
}

func (cfg *Config) validate() error {
	if cfg.LogBackend == nil {
		return fmt.Errorf("nonvoting/client: LogBackend is mandatory")
	}
	if cfg.AuthorityIdentityKey == nil {
		return fmt.Errorf("nonvoting/client: AuthorityIdentityKeyPublicKey is mandatory")
	}
	return nil
}

type client struct {
	cfg *Config
	log *logging.Logger

	serverLinkKey wire.PublicKey
}

func (c *client) Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.MixDescriptor) error {
	c.log.Debugf("Post(ctx, %d, %v, %+v)", epoch, signingPublicKey, d)

	// Ensure that the descriptor we are about to post is well formed.
	if err := s11n.IsDescriptorWellFormed(d, epoch); err != nil {
		return err
	}

	// Make a serialized + signed + serialized descriptor.
	signed, err := s11n.SignDescriptor(signingPrivateKey, d)
	if err != nil {
		return err
	}
	c.log.Debugf("Signed descriptor: '%v'", signed)

	// Initialize the TCP/IP connection, and wire session.
	doneCh := make(chan interface{})
	defer close(doneCh)
	conn, s, err := c.initSession(ctx, doneCh, signingPublicKey, c.cfg.LinkKey)
	if err != nil {
		return err
	}
	defer func() {
		s.Close()
		conn.Close()
	}()

	// Dispatch the post_descriptor command.
	cmd := &commands.PostDescriptor{
		Epoch:   epoch,
		Payload: []byte(signed),
	}
	resp, err := c.doRoundTrip(ctx, s, cmd)
	if err != nil {
		return err
	}

	// Parse the post_descriptor_status command.
	r, ok := resp.(*commands.PostDescriptorStatus)
	if !ok {
		return fmt.Errorf("nonvoting/client: Post() unexpected reply: %T", resp)
	}
	switch r.ErrorCode {
	case commands.DescriptorOk:
		return nil
	case commands.DescriptorConflict:
		return pki.ErrInvalidPostEpoch
	default:
		return fmt.Errorf("nonvoting/client: Post() rejected by authority: %v", postErrorToString(r.ErrorCode))
	}

	// NOTREACHED
}

func (c *client) Get(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	c.log.Debugf("Get(ctx, %d)", epoch)

	// Generate a random wire keypair to use for the link authentication.
	scheme := wire.NewScheme()
	linkKey := scheme.GenerateKeypair(rand.Reader)
	defer linkKey.Reset()

	// Initialize the TCP/IP connection, and wire session.
	doneCh := make(chan interface{})
	defer close(doneCh)

	conn, s, err := c.initSession(ctx, doneCh, nil, linkKey)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		s.Close()
		conn.Close()
	}()

	// Dispatch the get_consensus command.
	cmd := &commands.GetConsensus{Epoch: epoch}
	resp, err := c.doRoundTrip(ctx, s, cmd)
	if err != nil {
		return nil, nil, err
	}

	// Parse the consensus command.
	r, ok := resp.(*commands.Consensus)
	if !ok {
		return nil, nil, fmt.Errorf("nonvoting/client: Get() unexpected reply: %T", resp)
	}
	switch r.ErrorCode {
	case commands.ConsensusOk:
	case commands.ConsensusGone:
		return nil, nil, pki.ErrNoDocument
	default:
		return nil, nil, fmt.Errorf("nonvoting/Client: Get() rejected by authority: %v", getErrorToString(r.ErrorCode))
	}

	// Validate the document.
	doc, err := s11n.VerifyAndParseDocument(r.Payload, c.cfg.AuthorityIdentityKey)
	if err != nil {
		return nil, nil, err
	} else if doc.Epoch != epoch {
		c.log.Warningf("nonvoting/Client: Get() authority returned document for wrong epoch: %v", doc.Epoch)
		return nil, nil, s11n.ErrInvalidEpoch
	}
	c.log.Debugf("Document: %v", doc)

	return doc, r.Payload, nil
}

func (c *client) Deserialize(raw []byte) (*pki.Document, error) {
	return s11n.VerifyAndParseDocument(raw, c.cfg.AuthorityIdentityKey)
}

func (c *client) initSession(ctx context.Context, doneCh <-chan interface{}, signingKey sign.PublicKey, linkKey wire.PrivateKey) (net.Conn, *wire.Session, error) {
	// Connect to the peer.
	dialFn := c.cfg.DialContextFn
	if dialFn == nil {
		dialFn = defaultDialer.DialContext
	}
	conn, err := dialFn(ctx, "tcp", c.cfg.Address)
	if err != nil {
		return nil, nil, err
	}

	var isOk bool
	defer func() {
		if !isOk {
			conn.Close()
		}
	}()

	var ad []byte
	if signingKey != nil {
		keyHash := signingKey.Sum256()
		ad = keyHash[:]
	}

	// Initialize the wire protocol session.
	cfg := &wire.SessionConfig{
		Geometry:          sphinx.DefaultGeometry(),
		Authenticator:     c,
		AdditionalData:    ad,
		AuthenticationKey: linkKey,
		RandomReader:      rand.Reader,
	}
	s, err := wire.NewSession(cfg, true)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}

	isOk = true
	return conn, s, nil
}

func (c *client) IsPeerValid(creds *wire.PeerCredentials) bool {
	keyHash := c.cfg.AuthorityIdentityKey.Sum256()
	if !hmac.Equal(keyHash[:], creds.AdditionalData[:sign.PublicKeyHashSize]) {
		c.log.Warningf("nonvoting/Client: IsPeerValid(): AD mismatch: got %x != want %x", creds.AdditionalData, keyHash[:])
		return false
	}
	if !c.serverLinkKey.Equal(creds.PublicKey) {
		c.log.Warningf("nonvoting/Client: IsPeerValid(): Public Key mismatch: %v", creds.PublicKey)
		return false
	}
	return true
}

func (c *client) doRoundTrip(ctx context.Context, s *wire.Session, cmd commands.Command) (commands.Command, error) {
	if err := s.SendCommand(cmd); err != nil {
		return nil, err
	}
	return s.RecvCommand()
}

// New constructs a new pki.Client instance.
func New(cfg *Config) (pki.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nonvoting/client: cfg is mandatory")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	c := new(client)
	c.cfg = cfg
	c.log = cfg.LogBackend.GetLogger("pki/nonvoting/client")
	c.serverLinkKey = cfg.AuthorityLinkKey

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
