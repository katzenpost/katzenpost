// client.go - Katzenpost voting authority client.
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

// Package client implements the Katzenpost voting authority client.
package client

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/authority/internal/s11n"
	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

var defaultDialer = &net.Dialer{}

// authorityAuthenticator implements the PeerAuthenticator interface
type authorityAuthenticator struct {
	IdentityPublicKey sign.PublicKey
	LinkPublicKey     wire.PublicKey
	log               *logging.Logger
}

// IsPeerValid authenticates the remote peer's credentials, returning true
// iff the peer is valid.
func (a *authorityAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	identityHash := a.IdentityPublicKey.Sum256()
	if !hmac.Equal(identityHash[:], creds.AdditionalData[:sign.PublicKeyHashSize]) {
		a.log.Warningf("voting/Client: IsPeerValid(): AD mismatch: %x != %x", identityHash[:], creds.AdditionalData[:sign.PublicKeyHashSize])
		return false
	}
	if !bytes.Equal(a.LinkPublicKey.Bytes(), creds.PublicKey.Bytes()) {
		a.log.Warningf("voting/Client: IsPeerValid(): Link Public Key mismatch: %x != %x", a.LinkPublicKey.Bytes(), creds.PublicKey.Bytes())
		return false
	}
	return true
}

// Config is a voting authority pki.Client instance.
type Config struct {
	// DataDir is the absolute path to the directory
	// containing Authority link pub key PEM files.
	DataDir string

	// LinkKey is the link key for the client's wire connections.
	LinkKey wire.PrivateKey

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
		for _, a := range v.Addresses {
			if len(a) == 0 {
				return errors.New("voting/client: Invalid Address: zero length")
			}
		}
		if v.IdentityPublicKeyPem == "" {
			return fmt.Errorf("voting/client: Identity PublicKey is mandatory")
		}
		if v.LinkPublicKeyPem == "" {
			return fmt.Errorf("voting/client: Link PublicKey is mandatory")
		}
	}
	return nil
}

type connection struct {
	conn    net.Conn
	session *wire.Session
}

// connector is used to make connections.
type connector struct {
	cfg *Config
	log *logging.Logger
}

// newConnector returns a connector initialized from a Config.
func newConnector(cfg *Config) *connector {
	p := &connector{
		cfg: cfg,
		log: cfg.LogBackend.GetLogger("pki/voting/client/connector"),
	}
	return p
}

func (p *connector) initSession(ctx context.Context, doneCh <-chan interface{}, linkKey wire.PrivateKey, signingKey sign.PublicKey, peer *config.AuthorityPeer) (*connection, error) {
	var conn net.Conn
	var err error

	// Connect to the peer.
	dialFn := p.cfg.DialContextFn
	if dialFn == nil {
		dialFn = defaultDialer.DialContext
	}

	// permute the order the client tries Addresses
	r := rand.NewMath()
	idxs := r.Perm(len(peer.Addresses))

	// try each Address until a connection is successful or fail
	for i, idx := range idxs {
		conn, err = dialFn(ctx, "tcp", peer.Addresses[idx])
		if err == nil {
			break
		}
		if i == len(idxs)-1 {
			return nil, err
		}
	}

	var isOk bool
	defer func() {
		if !isOk {
			conn.Close()
		}
	}()

	peerLinkPublicKey, err := wire.DefaultScheme.PublicKeyFromPemFile(filepath.Join(p.cfg.DataDir, peer.LinkPublicKeyPem))
	if err != nil {
		return nil, err
	}

	_, peerIdPublicKey := cert.Scheme.NewKeypair()
	err = pem.FromFile(filepath.Join(p.cfg.DataDir, peer.IdentityPublicKeyPem), peerIdPublicKey)
	if err != nil {
		return nil, err
	}

	peerAuthenticator := &authorityAuthenticator{
		IdentityPublicKey: peerIdPublicKey,
		LinkPublicKey:     peerLinkPublicKey,
		log:               p.log,
	}

	// Initialize the wire protocol session.
	var ad []byte
	if signingKey != nil {
		keyHash := signingKey.Sum256()
		ad = keyHash[:]
	}
	cfg := &wire.SessionConfig{
		Geometry:          sphinx.DefaultGeometry(),
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

func (p *connector) roundTrip(s *wire.Session, cmd commands.Command) (commands.Command, error) {
	if err := s.SendCommand(cmd); err != nil {
		return nil, err
	}
	return s.RecvCommand()
}

func (p *connector) allPeersRoundTrip(ctx context.Context, linkKey wire.PrivateKey, signingKey sign.PublicKey, cmd commands.Command) ([]commands.Command, error) {
	doneCh := make(chan interface{})
	defer close(doneCh)
	responses := []commands.Command{}
	for _, peer := range p.cfg.Authorities {
		conn, err := p.initSession(ctx, doneCh, linkKey, signingKey, peer)
		if err != nil {
			p.log.Noticef("pki/voting/client: failure to connect to Authority peer %s", peer.IdentityPublicKeyPem)
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

func (p *connector) randomPeerRoundTrip(ctx context.Context, linkKey wire.PrivateKey, cmd commands.Command) (commands.Command, error) {
	doneCh := make(chan interface{})
	defer close(doneCh)

	if len(p.cfg.Authorities) == 0 {
		return nil, errors.New("error: zero Authorities specified in configuration")
	}

	r := rand.NewMath()
	peerIndex := r.Intn(len(p.cfg.Authorities))

	conn, err := p.initSession(ctx, doneCh, linkKey, nil, p.cfg.Authorities[peerIndex])
	if err != nil {
		return nil, err
	}
	resp, err := p.roundTrip(conn.session, cmd)
	return resp, err
}

// Client is a PKI client.
type Client struct {
	cfg       *Config
	log       *logging.Logger
	pool      *connector
	verifiers []cert.Verifier
	threshold int
}

// Post posts the node's descriptor to the PKI for the provided epoch.
func (c *Client) Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.MixDescriptor) error {
	// Ensure that the descriptor we are about to post is well formed.
	if err := s11n.IsDescriptorWellFormed(d, epoch); err != nil {
		return err
	}
	// Make a serialized + signed + serialized descriptor.
	signed, err := s11n.SignDescriptor(signingPrivateKey, d)
	if err != nil {
		return err
	}
	// Dispatch the post_descriptor command.
	cmd := &commands.PostDescriptor{
		Epoch:   epoch,
		Payload: []byte(signed),
	}
	responses, err := c.pool.allPeersRoundTrip(ctx, c.cfg.LinkKey, signingPublicKey, cmd)
	if err != nil {
		return err
	}
	// Parse the post_descriptor_status command.
	errs := []error{}
	for _, resp := range responses {
		r, ok := resp.(*commands.PostDescriptorStatus)
		if !ok {
			errs = append(errs, fmt.Errorf("voting/Client: Post() unexpected reply: %T", resp))
			continue
		}
		switch r.ErrorCode {
		case commands.DescriptorOk:
		case commands.DescriptorConflict:
			errs = append(errs, pki.ErrInvalidPostEpoch)
		default:
			errs = append(errs, fmt.Errorf("voting/Client: Post() rejected by authority: %v", postErrorToString(r.ErrorCode)))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("failure to Post to %d Directory Authorities", len(errs))
}

// Get returns the PKI document along with the raw serialized form for the provided epoch.
func (c *Client) Get(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	c.log.Debugf("Get(ctx, %d)", epoch)

	// Generate a random ecdh keypair to use for the link authentication.
	scheme := wire.DefaultScheme
	linkKey := scheme.GenerateKeypair(rand.Reader)
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
		return nil, nil, fmt.Errorf("voting/Client: Get() unexpected reply: %T", resp)
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
	_, good, bad, err := cert.VerifyThreshold(c.verifiers, c.threshold, r.Payload)
	if err != nil {
		c.log.Errorf("VerifyThreshold failure: %d good signatures, %d bad signatures: %v", len(good), len(bad), err)
		return nil, nil, fmt.Errorf("voting/Client: Get() invalid consensus document: %s", err)
	}
	if len(good) == len(c.cfg.Authorities) {
		c.log.Notice("OK, received fully signed consensus document.")
	}
	doc, err = s11n.VerifyAndParseDocument(r.Payload, good[0])
	if err != nil {
		c.log.Errorf("voting/Client: Get() invalid consensus document: %s", err)
		return nil, nil, err
	}
	if doc.Epoch != epoch {
		return nil, nil, fmt.Errorf("voting/Client: Get() consensus document for WRONG epoch: %v", doc.Epoch)
	}
	return doc, r.Payload, nil
}

// Deserialize returns PKI document given the raw bytes.
func (c *Client) Deserialize(raw []byte) (*pki.Document, error) {
	_, good, _, err := cert.VerifyThreshold(c.verifiers, c.threshold, raw)
	if err != nil {
		return nil, err
	}
	doc, err := s11n.VerifyAndParseDocument(raw, good[0])
	if err != nil {
		fmt.Errorf("Deserialize failure: %s", err)
	}
	return doc, err
}

// New constructs a new pki.Client instance.
func New(cfg *Config) (pki.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("voting/Client: cfg is mandatory")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	c := new(Client)
	c.cfg = cfg
	c.log = cfg.LogBackend.GetLogger("pki/voting/Client")
	c.pool = newConnector(cfg)
	c.verifiers = make([]cert.Verifier, len(c.cfg.Authorities))
	for i, auth := range c.cfg.Authorities {
		_, authIdPublicKey := cert.Scheme.NewKeypair()
		err := pem.FromFile(filepath.Join(c.cfg.DataDir, auth.IdentityPublicKeyPem), authIdPublicKey)
		if err != nil {
			return nil, err
		}
		c.verifiers[i] = cert.Verifier(authIdPublicKey)
	}
	c.threshold = len(c.verifiers)/2 + 1
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
