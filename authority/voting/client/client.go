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
	"net/url"
	"strings"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/quic/common"
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
		a.log.Warningf("voting/Client: IsPeerValid(): Remote Peer Credentials: additional_data=%x, public_key=%s", creds.AdditionalData, kempem.ToPublicPEMString(creds.PublicKey))
		return false
	}
	if !a.LinkPublicKey.Equal(creds.PublicKey) {
		a.log.Warningf("voting/Client: IsPeerValid(): Link Public Key mismatch: %s != %s", kempem.ToPublicPEMString(a.LinkPublicKey), kempem.ToPublicPEMString(creds.PublicKey))
		a.log.Warningf("voting/Client: IsPeerValid(): Remote Peer Credentials: additional_data=%x", creds.AdditionalData[:hash.HashSize])
		return false
	}
	return true
}

// Config is a voting authority pki.Client instance.
type Config struct {
	// KEMScheme indicates the KEM scheme used for the LinkKey/wire protocol.
	KEMScheme kem.Scheme

	// PKISignatureScheme specifies the cryptographic signature scheme
	PKISignatureScheme sign.Scheme

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

func (p *connector) initSession(ctx context.Context, linkKey kem.PrivateKey, signingKey sign.PublicKey, peer *config.Authority) (*connection, error) {
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
		u, err := url.Parse(peer.Addresses[idx])
		if err != nil {
			continue
		}
		ictx, cancelFn := context.WithCancel(ctx)
		conn, err = common.DialURL(u, ictx, dialFn)
		defer cancelFn()
		if err == nil {
			break
		}
		if i == len(peer.Addresses)-1 {
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
	if signingKey != nil {
		keyHash := hash.Sum256From(signingKey)
		ad = keyHash[:]
	}

	cfg := &wire.SessionConfig{
		KEMScheme:          schemes.ByName(peer.WireKEMScheme),
		PKISignatureScheme: signSchemes.ByName(peer.PKISignatureScheme),
		Geometry:           p.cfg.Geo,
		Authenticator:      peerAuthenticator,
		AdditionalData:     ad,
		AuthenticationKey:  linkKey,
		RandomReader:       rand.Reader,
	}
	s, err := wire.NewPKISession(cfg, true)
	if err != nil {
		return nil, err
	}

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

// PeerResponse represents a response from a specific peer
type PeerResponse struct {
	Peer     *config.Authority
	Response commands.Command
	Error    error
}

func (p *connector) allPeersRoundTrip(ctx context.Context, linkKey kem.PrivateKey, signingKey sign.PublicKey, cmd commands.Command) ([]PeerResponse, error) {
	peerResponses := []PeerResponse{}
	for _, peer := range p.cfg.Authorities {
		ictx, cancelFn := context.WithCancel(ctx)
		defer cancelFn()
		conn, err := p.initSession(ictx, linkKey, signingKey, peer)
		if err != nil {
			p.log.Noticef("pki/voting/client: failure to connect to Authority %s (%x)\n", peer.Identifier, hash.Sum256From(peer.IdentityPublicKey))
			peerResponses = append(peerResponses, PeerResponse{
				Peer:  peer,
				Error: fmt.Errorf("connection failed: %v", err),
			})
			continue
		}
		resp, err := p.roundTrip(conn.session, cmd)
		if err != nil {
			p.log.Noticef("pki/voting/client: failure in sending command to Authority peer %s: %s", peer, err)
			peerResponses = append(peerResponses, PeerResponse{
				Peer:  peer,
				Error: fmt.Errorf("round trip failed: %v", err),
			})
			continue
		}
		peerResponses = append(peerResponses, PeerResponse{
			Peer:     peer,
			Response: resp,
		})
	}
	if len(peerResponses) == 0 {
		return nil, errors.New("allPeerRoundTrip failure, got zero responses")
	}
	return peerResponses, nil
}

func (p *connector) fetchConsensus(auth *config.Authority, ctx context.Context, linkKey kem.PrivateKey, epoch uint64) (commands.Command, error) {
	if len(p.cfg.Authorities) == 0 {
		return nil, errors.New("error: zero Authorities specified in configuration")
	}

	conn, err := p.initSession(ctx, linkKey, nil, auth)
	if err != nil {
		return nil, fmt.Errorf("peer %s (%s, identity=%s, link=%s): connection failed: %v",
			auth.Identifier,
			strings.Join(auth.Addresses, ","),
			strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
			strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
			err)
	}
	p.log.Debugf("sending getConsensus to %s", auth.Identifier)
	p.log.Debugf("remote peer %s identity key: %s", auth.Identifier, strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)))
	p.log.Debugf("remote peer %s link key: %s", auth.Identifier, strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)))
	cmd := &commands.GetConsensus{
		Epoch:              epoch,
		Cmds:               commands.NewPKICommands(p.cfg.PKISignatureScheme),
		MixnetTransmission: false, // Disable padding for direct dirauth transmission
	}
	resp, err := p.roundTrip(conn.session, cmd)
	if err != nil {
		r, ok := resp.(*commands.Consensus)
		if !ok {
			return nil, fmt.Errorf("peer %s (%s, identity=%s, link=%s): round trip failed: %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				err)
		} else {
			p.log.Noticef("got response from %s to GetConsensus(%d) (err=%v res=%s)", auth.Identifier, epoch, err, getErrorToString(r.ErrorCode))
			return nil, fmt.Errorf("peer %s (%s, identity=%s, link=%s): consensus error: %v (%s)",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				err, getErrorToString(r.ErrorCode))
		}
	}
	r, ok := resp.(*commands.Consensus)
	if !ok {
		return nil, fmt.Errorf("peer %s (%s, identity=%s, link=%s): invalid command type: %T",
			auth.Identifier,
			strings.Join(auth.Addresses, ","),
			strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
			strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
			resp)
	}

	return r, nil
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
	peerResponses, err := c.pool.allPeersRoundTrip(ctx, c.cfg.LinkKey, signingPublicKey, cmd)
	if err != nil {
		return err
	}
	// Parse the post_descriptor_status command.
	errs := []error{}
	for _, peerResp := range peerResponses {
		if peerResp.Error != nil {
			errs = append(errs, fmt.Errorf("peer %s (%s, identity=%s, link=%s): %v",
				peerResp.Peer.Identifier,
				strings.Join(peerResp.Peer.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(peerResp.Peer.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(peerResp.Peer.LinkPublicKey)),
				peerResp.Error))
			continue
		}
		r, ok := peerResp.Response.(*commands.PostDescriptorStatus)
		if !ok {
			errs = append(errs, fmt.Errorf("peer %s (%s, identity=%s, link=%s): unexpected reply: %T",
				peerResp.Peer.Identifier,
				strings.Join(peerResp.Peer.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(peerResp.Peer.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(peerResp.Peer.LinkPublicKey)),
				peerResp.Response))
			continue
		}
		switch r.ErrorCode {
		case commands.DescriptorOk:
		case commands.DescriptorConflict:
			errs = append(errs, fmt.Errorf("peer %s (%s, identity=%s, link=%s): %v",
				peerResp.Peer.Identifier,
				strings.Join(peerResp.Peer.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(peerResp.Peer.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(peerResp.Peer.LinkPublicKey)),
				pki.ErrInvalidPostEpoch))
		default:
			errs = append(errs, fmt.Errorf("peer %s (%s, identity=%s, link=%s): rejected by authority: %v",
				peerResp.Peer.Identifier,
				strings.Join(peerResp.Peer.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(peerResp.Peer.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(peerResp.Peer.LinkPublicKey)),
				postErrorToString(r.ErrorCode)))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("failure to Post(%d) to Directory Authorities: %v", epoch, errs)
}

// PostReplica posts the node's descriptor to the PKI for the provided epoch.
func (c *Client) PostReplica(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.ReplicaDescriptor) error {
	// Ensure that the descriptor we are about to post is well formed.
	if err := pki.IsReplicaDescriptorWellFormed(d, epoch); err != nil {
		return err
	}
	signedUpload := &pki.SignedReplicaUpload{
		ReplicaDescriptor: d,
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
	cmd := &commands.PostReplicaDescriptor{
		Epoch:   epoch,
		Payload: []byte(signed),
	}
	peerResponses, err := c.pool.allPeersRoundTrip(ctx, c.cfg.LinkKey, signingPublicKey, cmd)
	if err != nil {
		return err
	}
	// Parse the post_descriptor_status command.
	errs := []error{}
	for _, peerResp := range peerResponses {
		if peerResp.Error != nil {
			errs = append(errs, fmt.Errorf("peer %s (%s, identity=%s, link=%s): %v",
				peerResp.Peer.Identifier,
				strings.Join(peerResp.Peer.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(peerResp.Peer.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(peerResp.Peer.LinkPublicKey)),
				peerResp.Error))
			continue
		}
		r, ok := peerResp.Response.(*commands.PostDescriptorStatus)
		if !ok {
			errs = append(errs, fmt.Errorf("peer %s (%s, identity=%s, link=%s): unexpected reply: %T",
				peerResp.Peer.Identifier,
				strings.Join(peerResp.Peer.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(peerResp.Peer.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(peerResp.Peer.LinkPublicKey)),
				peerResp.Response))
			continue
		}
		switch r.ErrorCode {
		case commands.DescriptorOk:
		case commands.DescriptorConflict:
			errs = append(errs, fmt.Errorf("peer %s (%s, identity=%s, link=%s): %v",
				peerResp.Peer.Identifier,
				strings.Join(peerResp.Peer.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(peerResp.Peer.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(peerResp.Peer.LinkPublicKey)),
				pki.ErrInvalidPostEpoch))
		default:
			errs = append(errs, fmt.Errorf("peer %s (%s, identity=%s, link=%s): rejected by authority: %v",
				peerResp.Peer.Identifier,
				strings.Join(peerResp.Peer.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(peerResp.Peer.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(peerResp.Peer.LinkPublicKey)),
				postErrorToString(r.ErrorCode)))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("failure to Post(%d) to Directory Authorities: %v", epoch, errs)
}

// Get returns the PKI document along with the raw serialized form for the provided epoch.
func (c *Client) Get(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	c.log.Noticef("Get(ctx, %d)", epoch)

	// Generate a random keypair to use for the link authentication.
	_, linkKey, err := c.cfg.KEMScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// permute the order the client tries Authorities
	r := rand.NewMath()
	idxs := r.Perm(len(c.cfg.Authorities))

	// Collect detailed error information from each peer
	var peerErrors []error

	for _, idx := range idxs {
		auth := c.cfg.Authorities[idx]
		ctx, cancelFn := context.WithCancel(ctx)
		resp, err := c.pool.fetchConsensus(auth, ctx, linkKey, epoch)
		defer cancelFn()
		if err != nil {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): fetchConsensus failed: %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				err)
			c.log.Errorf("GetConsensus from %s failed: %s", auth.Identifier, err)
			peerErrors = append(peerErrors, peerErr)
			continue
		}

		// Parse the consensus command.
		r, ok := resp.(*commands.Consensus)
		if !ok {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): unexpected reply: %T",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				resp)
			c.log.Errorf("GetConsensus from %s returned unexpected reply: %T", auth.Identifier, resp)
			peerErrors = append(peerErrors, peerErr)
			continue
		}
		switch r.ErrorCode {
		case commands.ConsensusOk:
		case commands.ConsensusGone:
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): consensus gone",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)))
			c.log.Errorf("GetConsensus from %s returned ConsensusGone", auth.Identifier)
			peerErrors = append(peerErrors, peerErr)
			continue
		case commands.ConsensusNotFound:
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): consensus not found",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)))
			c.log.Errorf("GetConsensus from %s returned ConsensusNotFound", auth.Identifier)
			peerErrors = append(peerErrors, peerErr)
			continue
		default:
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): rejected with %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				getErrorToString(r.ErrorCode))
			c.log.Errorf("GetConsensus from %s rejected with %v", auth.Identifier, getErrorToString(r.ErrorCode))
			peerErrors = append(peerErrors, peerErr)
			continue
		}

		// Verify document signatures.
		doc := &pki.Document{}
		_, good, bad, err := cert.VerifyThreshold(c.verifiers, c.threshold, r.Payload)
		if err != nil {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): signature verification failed: %d good, %d bad: %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				len(good), len(bad), err)
			c.log.Errorf("VerifyThreshold failure: %d good signatures, %d bad signatures: %v", len(good), len(bad), err)
			peerErrors = append(peerErrors, peerErr)
			continue
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
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): invalid consensus document: %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				err)
			c.log.Errorf("voting/Client: Get() invalid consensus document: %s", err)
			peerErrors = append(peerErrors, peerErr)
			continue
		}

		err = pki.IsDocumentWellFormed(doc, c.verifiers)
		if err != nil {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): document not well formed: %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				err)
			c.log.Errorf("voting/Client: IsDocumentWellFormed: %s", err)
			peerErrors = append(peerErrors, peerErr)
			continue
		}

		if doc.Epoch != epoch {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): wrong epoch: got %d, expected %d",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				doc.Epoch, epoch)
			c.log.Errorf("voting/Client: Get() consensus document for WRONG epoch: %v", doc.Epoch)
			peerErrors = append(peerErrors, peerErr)
			continue
		}
		c.log.Debugf("voting/Client: Get() document:\n%s", doc)
		return doc, r.Payload, nil
	}

	// All authorities failed, return detailed error information
	e, _, _ := epochtime.Now()
	if len(peerErrors) > 0 {
		if epoch <= e {
			return nil, nil, fmt.Errorf("failed to get consensus document (epoch %d <= current %d): %v", epoch, e, peerErrors)
		} else {
			return nil, nil, fmt.Errorf("failed to get consensus document (epoch %d > current %d): %v", epoch, e, peerErrors)
		}
	}

	// Fallback to original errors if no peer errors collected
	if epoch <= e {
		return nil, nil, pki.ErrDocumentGone
	} else {
		return nil, nil, pki.ErrNoDocument
	}
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
