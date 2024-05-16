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
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"net"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/loops"
)

var defaultDialer = &net.Dialer{}

// authorityAuthenticator implements the PeerAuthenticator interface
type authorityAuthenticator struct {
	IdentityPublicKey sign.PublicKey
	LinkPublicKey     kem.PublicKey
	log               *logging.Logger
}

// IsPeerValid authenticates the remote peer's credentials, returning true
// iff the peer is valid.
func (a *authorityAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	identityHash := hash.Sum256From(a.IdentityPublicKey)
	if !hmac.Equal(identityHash[:], creds.AdditionalData[:hash.HashSize]) {
		a.log.Warningf("voting/Client: IsPeerValid(): AD mismatch: %x != %x", identityHash[:], creds.AdditionalData[:hash.HashSize])
		return false
	}
	if !a.LinkPublicKey.Equal(creds.PublicKey) {
		a.log.Warningf("voting/Client: IsPeerValid(): Link Public Key mismatch: %s != %s", kempem.ToPublicPEMString(a.LinkPublicKey), kempem.ToPublicPEMString(creds.PublicKey))
		return false
	}
	return true
}

// Config is a voting authority pki.Client instance.
type Config struct {
	// KEMScheme indicates the KEM scheme used for the LinkKey/wire protocol.
	KEMScheme kem.Scheme

	// LinkKey is the link key for the client's wire connections.
	LinkKey kem.PrivateKey

	// LogBackend is the `core/log` Backend instance to use for logging.
	LogBackend *log.Backend

	// Authorities is the set of Directory Authority servers.
	Authorities []*config.Authority

	// DialContextFn is the optional alternative Dialer.DialContext function
	// to be used when creating outgoing network connections.
	DialContextFn func(ctx context.Context, network, address string) (net.Conn, error)

	// Geo is the geometry used for the Sphinx packet construction.
	Geo *geo.Geometry
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

func (p *connector) initSession(ctx context.Context, doneCh <-chan interface{}, linkKey kem.PrivateKey, signingKey sign.PublicKey, peer *config.Authority) (*connection, error) {
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

	peerAuthenticator := &authorityAuthenticator{
		IdentityPublicKey: peer.IdentityPublicKey,
		LinkPublicKey:     peer.LinkPublicKey,
		log:               p.log,
	}

	// Initialize the wire protocol session.
	var ad []byte
	var pkiSignatureScheme sign.Scheme
	if signingKey != nil {
		keyHash := hash.Sum256From(signingKey)
		ad = keyHash[:]
		pkiSignatureScheme = signSchemes.ByName(signingKey.Scheme().Name())
	} else {
		pkiSignatureScheme = signSchemes.ByName("Ed25519 Sphincs+") // todo fix me
	}
	cfg := &wire.SessionConfig{
		KEMScheme:          schemes.ByName(peer.WireKEMScheme),
		Geometry:           p.cfg.Geo,
		Authenticator:      peerAuthenticator,
		AdditionalData:     ad,
		AuthenticationKey:  linkKey,
		RandomReader:       rand.Reader,
		PKISignatureScheme: pkiSignatureScheme,
	}
	s, err := wire.NewPKISession(cfg, true)
	if err != nil {
		return nil, err
	}

	go func() {
		select {
		case <-ctx.Done():
			p.log.Warning("closing connection due to context Done event... most likely a timeout")
			conn.Close()
		case <-doneCh:
		}
	}()

	// Handshake.
	if err = s.Initialize(conn); err != nil {
		conn.Close()
		return nil, err
	}

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

func (p *connector) allPeersRoundTrip(ctx context.Context, linkKey kem.PrivateKey, signingKey sign.PublicKey, cmd commands.Command) ([]commands.Command, error) {
	doneCh := make(chan interface{})
	defer close(doneCh)
	responses := []commands.Command{}
	for _, peer := range p.cfg.Authorities {
		conn, err := p.initSession(ctx, doneCh, linkKey, signingKey, peer)
		if err != nil {
			p.log.Noticef("pki/voting/client: failure to connect to Authority %s (%x)\n", peer.Identifier, hash.Sum256From(peer.IdentityPublicKey))
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

func (p *connector) fetchConsensus(ctx context.Context, linkKey kem.PrivateKey, epoch uint64) (commands.Command, error) {
	doneCh := make(chan interface{})
	defer close(doneCh)

	if len(p.cfg.Authorities) == 0 {
		return nil, errors.New("error: zero Authorities specified in configuration")
	}

	r := rand.NewMath()
	peerIndex := r.Intn(len(p.cfg.Authorities))

	// try each authority
	for i := 0; i < len(p.cfg.Authorities); i++ {
		auth := p.cfg.Authorities[(peerIndex+i)%len(p.cfg.Authorities)]
		conn, err := p.initSession(ctx, doneCh, linkKey, nil, auth)
		if err != nil {
			return nil, err
		}
		p.log.Noticef("sending getConsensus to %s", auth.Identifier)
		cmd := &commands.GetConsensus{Epoch: epoch, Cmds: conn.session.GetCommands()}
		resp, err := p.roundTrip(conn.session, cmd)

		if err != nil {
			p.log.Errorf("voting/Client: GetConsensus() error from %v %s", err, auth.Identifier)
			continue
		}

		r, ok := resp.(*commands.Consensus)
		if !ok {
			p.log.Errorf("voting/Client: GetConsensus() unexpected reply from %s %T", auth.Identifier, resp)
			continue
		}

		p.log.Noticef("got response from %s to GetConsensus(%d) (attempt %d, err=%v, res=%s)", auth.Identifier, epoch, i, err, getErrorToString(r.ErrorCode))
		if err == pki.ErrNoDocument {
			continue
		}
		return resp, err
	}
	return nil, pki.ErrNoDocument
}

// Client is a PKI client.
type Client struct {
	cfg       *Config
	log       *logging.Logger
	pool      *connector
	verifiers []sign.PublicKey
	threshold int
}

// Post posts the node's descriptor to the PKI for the provided epoch.
func (c *Client) Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.MixDescriptor, loopstats *loops.LoopStats) error {
	// Ensure that the descriptor we are about to post is well formed.
	if err := pki.IsDescriptorWellFormed(d, epoch); err != nil {
		return err
	}
	signedUpload := &pki.SignedUpload{
		MixDescriptor: d,
		LoopStats:     loopstats,
	}
	blob, err := signedUpload.Marshal()
	if err != nil {
		return err
	}
	signedUpload.Signature = &cert.Signature{
		PublicKeySum256: hash.Sum256From(signingPublicKey),
		Payload:         signingPrivateKey.Scheme().Sign(signingPrivateKey, blob, nil),
	}
	signed, err := signedUpload.Marshal()
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
	return fmt.Errorf("failure to Post(%d) to %d Directory Authorities: %v", epoch, len(errs), errs)
}

// Get returns the PKI document along with the raw serialized form for the provided epoch.
func (c *Client) Get(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	c.log.Noticef("Get(ctx, %d)", epoch)

	// Generate a random keypair to use for the link authentication.
	_, linkKey, err := c.cfg.KEMScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Initialize the TCP/IP connection, and wire session.
	doneCh := make(chan interface{})
	defer close(doneCh)

	// Dispatch the get_consensus command.
	resp, err := c.pool.fetchConsensus(ctx, linkKey, epoch)
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
	} else {
		c.log.Noticef("OK, received consensus document with %d of %d signatures)", len(good), len(c.cfg.Authorities))
		for _, auth := range c.cfg.Authorities {
			for _, badauth := range bad {
				if badauth == auth.IdentityPublicKey {
					c.log.Noticef("missing or invalid signature from %s", auth.Identifier)
					break
				}
			}
		}
	}
	doc, err = pki.ParseDocument(r.Payload)
	if err != nil {
		c.log.Errorf("voting/Client: Get() invalid consensus document: %s", err)
		return nil, nil, err
	}

	err = pki.IsDocumentWellFormed(doc, c.verifiers)
	if err != nil {
		c.log.Errorf("voting/Client: IsDocumentWellFormed: %s", err)
		return nil, nil, err
	}

	if doc.Epoch != epoch {
		return nil, nil, fmt.Errorf("voting/Client: Get() consensus document for WRONG epoch: %v", doc.Epoch)
	}
	c.log.Noticef("voting/Client: Get() document:\n%s", doc)
	return doc, r.Payload, nil
}

// Deserialize returns PKI document given the raw bytes.
func (c *Client) Deserialize(raw []byte) (*pki.Document, error) {
	_, _, _, err := cert.VerifyThreshold(c.verifiers, c.threshold, raw)
	if err != nil {
		return nil, err
	}
	doc, err := pki.ParseDocument(raw)
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
	c.verifiers = make([]sign.PublicKey, len(c.cfg.Authorities))
	for i, auth := range c.cfg.Authorities {
		c.verifiers[i] = auth.IdentityPublicKey
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
