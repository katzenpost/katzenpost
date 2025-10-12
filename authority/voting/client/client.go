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
	"time"

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
	kpcommon "github.com/katzenpost/katzenpost/common"
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
		a.log.Warningf("voting/Client: IsPeerValid(): Expected identity key: %s (hash: %x)",
			kpcommon.TruncatePEMForLogging(signpem.ToPublicPEMString(a.IdentityPublicKey)), identityHash[:])
		a.log.Warningf("voting/Client: IsPeerValid(): Remote Peer Credentials: additional_data=%x, link_key=%s",
			creds.AdditionalData, kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(creds.PublicKey)))
		return false
	}
	if !a.LinkPublicKey.Equal(creds.PublicKey) {
		a.log.Warningf("voting/Client: IsPeerValid(): Link Public Key mismatch")
		a.log.Warningf("voting/Client: IsPeerValid(): Expected link key: %s",
			kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(a.LinkPublicKey)))
		a.log.Warningf("voting/Client: IsPeerValid(): Received link key: %s",
			kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(creds.PublicKey)))
		a.log.Warningf("voting/Client: IsPeerValid(): Expected identity key: %s (hash: %x)",
			kpcommon.TruncatePEMForLogging(signpem.ToPublicPEMString(a.IdentityPublicKey)), identityHash[:])
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

	// Network timeouts (seconds) - should match server config
	DialTimeoutSec      int // TCP connection (default: 30)
	HandshakeTimeoutSec int // Wire handshake (default: 180)
	ResponseTimeoutSec  int // Command exchange (default: 90)
}

func (cfg *Config) validate() error {
	// Set timeout defaults if not specified (same as server)
	if cfg.DialTimeoutSec == 0 {
		cfg.DialTimeoutSec = 30
	}
	if cfg.HandshakeTimeoutSec == 0 {
		cfg.HandshakeTimeoutSec = 180
	}
	if cfg.ResponseTimeoutSec == 0 {
		cfg.ResponseTimeoutSec = 90
	}

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

	// Helper function to create peer info string
	peerInfo := func() string {
		return fmt.Sprintf("peer %s (%s, identity=%s, link=%s)",
			peer.Identifier,
			strings.Join(peer.Addresses, ","),
			kpcommon.TruncatePEMForLogging(signpem.ToPublicPEMString(peer.IdentityPublicKey)),
			kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(peer.LinkPublicKey)))
	}

	// Connect to the peer.
	dialTimeout := time.Duration(p.cfg.DialTimeoutSec) * time.Second
	handshakeTimeout := time.Duration(p.cfg.HandshakeTimeoutSec) * time.Second
	responseTimeout := time.Duration(p.cfg.ResponseTimeoutSec) * time.Second

	p.log.Debugf("Client timeouts: dial=%v, handshake=%v, response=%v",
		dialTimeout, handshakeTimeout, responseTimeout)

	dialFn := p.cfg.DialContextFn
	if dialFn == nil {
		dialer := &net.Dialer{Timeout: dialTimeout}
		dialFn = dialer.DialContext
	}

	// permute the order the client tries Addresses
	r := rand.NewMath()
	idxs := r.Perm(len(peer.Addresses))

	// try each Address until a connection is successful or fail
	var lastErr error
	for i, idx := range idxs {
		u, err := url.Parse(peer.Addresses[idx])
		if err != nil {
			lastErr = fmt.Errorf("%s: invalid URL %s: %v", peerInfo(), peer.Addresses[idx], err)
			continue
		}
		ictx, cancelFn := context.WithCancel(ctx)
		conn, err = common.DialURL(u, ictx, dialFn)
		defer cancelFn()
		if err == nil {
			break
		}
		lastErr = fmt.Errorf("%s: failed to connect to %s: %v", peerInfo(), peer.Addresses[idx], err)
		if i == len(peer.Addresses)-1 {
			return nil, fmt.Errorf("%s: all connection attempts failed, last error: %v", peerInfo(), lastErr)
		}
	}

	peerAuthenticator := &authorityAuthenticator{
		IdentityPublicKey: peer.IdentityPublicKey,
		LinkPublicKey:     peer.LinkPublicKey,
		log:               p.log,
	}

	// Initialize the wire protocol session.
	var ad []byte
	var signingKeyInfo string
	if signingKey != nil {
		keyHash := hash.Sum256From(signingKey)
		ad = keyHash[:]
		signingKeyInfo = fmt.Sprintf(", signing_key=%s", kpcommon.TruncatePEMForLogging(signpem.ToPublicPEMString(signingKey)))
	} else {
		signingKeyInfo = ", signing_key=none"
	}

	// Get scheme information for error reporting
	kemScheme := schemes.ByName(peer.WireKEMScheme)
	if kemScheme == nil {
		return nil, fmt.Errorf("%s: unsupported KEM scheme: %s", peerInfo(), peer.WireKEMScheme)
	}

	var signatureScheme sign.Scheme
	if peer.PKISignatureScheme != "" {
		signatureScheme = signSchemes.ByName(peer.PKISignatureScheme)
		if signatureScheme == nil {
			return nil, fmt.Errorf("%s: unsupported signature scheme: %s", peerInfo(), peer.PKISignatureScheme)
		}
	}

	cfg := &wire.SessionConfig{
		KEMScheme:          kemScheme,
		PKISignatureScheme: signatureScheme,
		Geometry:           p.cfg.Geo,
		Authenticator:      peerAuthenticator,
		AdditionalData:     ad,
		AuthenticationKey:  linkKey,
		RandomReader:       rand.Reader,
	}
	s, err := wire.NewPKISession(cfg, true)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create PKI session (connection: %s -> %s, KEM: %s, signature: %s%s): %v",
			peerInfo(), conn.LocalAddr(), conn.RemoteAddr(),
			peer.WireKEMScheme, peer.PKISignatureScheme, signingKeyInfo, err)
	}

	// Handshake.
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err = s.Initialize(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: handshake failed (connection: %s -> %s, KEM: %s, signature: %s%s): %v",
			peerInfo(), conn.LocalAddr(), conn.RemoteAddr(),
			peer.WireKEMScheme, peer.PKISignatureScheme, signingKeyInfo, err)
	}

	// Set response timeout for command exchange
	conn.SetDeadline(time.Now().Add(responseTimeout))

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
	p.log.Debugf("allPeersRoundTrip: Starting round trip to %d authorities", len(p.cfg.Authorities))
	peerResponses := []PeerResponse{}
	successfulConnections := 0
	failedConnections := 0

	for i, peer := range p.cfg.Authorities {
		p.log.Debugf("allPeersRoundTrip: Attempting connection %d/%d to authority %s", i+1, len(p.cfg.Authorities), peer.Identifier)
		ictx, cancelFn := context.WithCancel(ctx)
		defer cancelFn()
		conn, err := p.initSession(ictx, linkKey, signingKey, peer)
		if err != nil {
			failedConnections++
			p.log.Errorf("allPeersRoundTrip: Failed to connect to authority %s (%x): %v", peer.Identifier, hash.Sum256From(peer.IdentityPublicKey), err)
			peerResponses = append(peerResponses, PeerResponse{
				Peer:  peer,
				Error: fmt.Errorf("connection failed: %v", err),
			})
			continue
		}
		p.log.Debugf("allPeersRoundTrip: Successfully connected to authority %s", peer.Identifier)

		resp, err := p.roundTrip(conn.session, cmd)
		if err != nil {
			failedConnections++
			p.log.Errorf("allPeersRoundTrip: Round trip failed to authority %s: %s", peer.Identifier, err)
			peerResponses = append(peerResponses, PeerResponse{
				Peer:  peer,
				Error: fmt.Errorf("round trip failed: %v", err),
			})
			continue
		}
		successfulConnections++
		p.log.Debugf("allPeersRoundTrip: Successfully completed round trip to authority %s", peer.Identifier)
		peerResponses = append(peerResponses, PeerResponse{
			Peer:     peer,
			Response: resp,
		})
	}

	p.log.Debugf("allPeersRoundTrip: Completed round trip attempts: %d successful, %d failed out of %d total", successfulConnections, failedConnections, len(p.cfg.Authorities))

	if len(peerResponses) == 0 {
		p.log.Errorf("allPeersRoundTrip: CRITICAL FAILURE - got zero responses from all %d authorities", len(p.cfg.Authorities))
		return nil, errors.New("allPeerRoundTrip failure, got zero responses")
	}
	return peerResponses, nil
}

func (p *connector) fetchConsensus(auth *config.Authority, ctx context.Context, linkKey kem.PrivateKey, epoch uint64) (commands.Command, error) {
	p.log.Debugf("fetchConsensus: Starting consensus fetch from authority %s for epoch %d", auth.Identifier, epoch)

	if len(p.cfg.Authorities) == 0 {
		p.log.Errorf("fetchConsensus: CONFIGURATION ERROR - zero authorities specified")
		return nil, errors.New("error: zero Authorities specified in configuration")
	}

	p.log.Debugf("fetchConsensus: Initializing session with authority %s (addresses: %s)", auth.Identifier, strings.Join(auth.Addresses, ","))
	conn, err := p.initSession(ctx, linkKey, nil, auth)
	if err != nil {
		p.log.Errorf("fetchConsensus: Session initialization failed with authority %s: %v", auth.Identifier, err)
		return nil, fmt.Errorf("peer %s (%s, identity=%s, link=%s): connection failed: %v",
			auth.Identifier,
			strings.Join(auth.Addresses, ","),
			kpcommon.TruncatePEMForLogging(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
			kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(auth.LinkPublicKey)),
			err)
	}
	p.log.Debugf("fetchConsensus: Successfully established session with authority %s", auth.Identifier)

	// Removed verbose debug logs that print keys
	cmd := &commands.GetConsensus{
		Epoch:              epoch,
		Cmds:               commands.NewPKICommands(p.cfg.PKISignatureScheme),
		MixnetTransmission: false, // Disable padding for direct dirauth transmission
	}
	p.log.Debugf("fetchConsensus: Sending GetConsensus command to authority %s for epoch %d", auth.Identifier, epoch)

	resp, err := p.roundTrip(conn.session, cmd)
	if err != nil {
		p.log.Errorf("fetchConsensus: Round trip failed to authority %s for epoch %d: %v", auth.Identifier, epoch, err)
		r, ok := resp.(*commands.Consensus)
		if !ok {
			p.log.Errorf("fetchConsensus: Round trip failed and response is not Consensus type from authority %s", auth.Identifier)
			return nil, fmt.Errorf("peer %s (%s, identity=%s, link=%s): round trip failed: %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				kpcommon.TruncatePEMForLogging(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				err)
		} else {
			p.log.Errorf("fetchConsensus: Got consensus response with error from authority %s for epoch %d: error=%v, errorCode=%s", auth.Identifier, epoch, err, getErrorToString(r.ErrorCode))
			return nil, fmt.Errorf("peer %s (%s, identity=%s, link=%s): consensus error: %v (%s)",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				err, getErrorToString(r.ErrorCode))
		}
	}
	p.log.Debugf("fetchConsensus: Successfully received response from authority %s for epoch %d", auth.Identifier, epoch)

	r, ok := resp.(*commands.Consensus)
	if !ok {
		p.log.Errorf("fetchConsensus: Response from authority %s is not Consensus type: %T", auth.Identifier, resp)
		return nil, fmt.Errorf("peer %s (%s, identity=%s, link=%s): invalid command type: %T",
			auth.Identifier,
			strings.Join(auth.Addresses, ","),
			strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
			strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
			resp)
	}

	p.log.Debugf("fetchConsensus: Successfully fetched consensus from authority %s for epoch %d", auth.Identifier, epoch)
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
	successCount := 0

	c.log.Noticef("📤 DESCRIPTOR POST: Processing responses from %d authorities for epoch %d", len(peerResponses), epoch)

	for _, peerResp := range peerResponses {
		peerInfo := fmt.Sprintf("peer %s (%s, identity=%s, link=%s)",
			peerResp.Peer.Identifier,
			strings.Join(peerResp.Peer.Addresses, ","),
			strings.TrimSpace(signpem.ToPublicPEMString(peerResp.Peer.IdentityPublicKey)),
			strings.TrimSpace(kempem.ToPublicPEMString(peerResp.Peer.LinkPublicKey)))

		if peerResp.Error != nil {
			c.log.Errorf("❌ DESCRIPTOR POST: Connection/transport error to %s: %v", peerResp.Peer.Identifier, peerResp.Error)
			errs = append(errs, fmt.Errorf("%s: %v", peerInfo, peerResp.Error))
			continue
		}

		r, ok := peerResp.Response.(*commands.PostDescriptorStatus)
		if !ok {
			c.log.Errorf("❌ DESCRIPTOR POST: Invalid response type from %s: got %T, expected PostDescriptorStatus",
				peerResp.Peer.Identifier, peerResp.Response)
			errs = append(errs, fmt.Errorf("%s: unexpected reply: %T", peerInfo, peerResp.Response))
			continue
		}

		switch r.ErrorCode {
		case commands.DescriptorOk:
			c.log.Noticef("✅ DESCRIPTOR POST: Successfully uploaded to %s for epoch %d", peerResp.Peer.Identifier, epoch)
			successCount++
		case commands.DescriptorConflict:
			c.log.Errorf("❌ DESCRIPTOR POST: Conflict/Late descriptor rejected by %s for epoch %d", peerResp.Peer.Identifier, epoch)
			errs = append(errs, fmt.Errorf("%s: %v", peerInfo, pki.ErrInvalidPostEpoch))
		case commands.DescriptorForbidden:
			c.log.Errorf("❌ DESCRIPTOR POST: Descriptor forbidden by %s for epoch %d - likely authorization failure", peerResp.Peer.Identifier, epoch)
			errs = append(errs, fmt.Errorf("%s: rejected by authority: %v (FORBIDDEN - check authorization)", peerInfo, postErrorToString(r.ErrorCode)))
		case commands.DescriptorInvalid:
			c.log.Errorf("❌ DESCRIPTOR POST: Invalid descriptor rejected by %s for epoch %d - malformed descriptor", peerResp.Peer.Identifier, epoch)
			errs = append(errs, fmt.Errorf("%s: rejected by authority: %v (INVALID - malformed descriptor)", peerInfo, postErrorToString(r.ErrorCode)))
		default:
			c.log.Errorf("❌ DESCRIPTOR POST: Unknown error from %s for epoch %d: %v", peerResp.Peer.Identifier, epoch, postErrorToString(r.ErrorCode))
			errs = append(errs, fmt.Errorf("%s: rejected by authority: %v", peerInfo, postErrorToString(r.ErrorCode)))
		}
	}

	c.log.Noticef("📊 DESCRIPTOR POST SUMMARY: %d successes, %d failures out of %d authorities for epoch %d",
		successCount, len(errs), len(peerResponses), epoch)

	// Calculate threshold (majority of authorities)
	threshold := (len(peerResponses) / 2) + 1

	if successCount >= threshold {
		if len(errs) > 0 {
			c.log.Noticef("✅ DESCRIPTOR POST: Upload successful - reached threshold (%d/%d), ignoring %d failures",
				successCount, threshold, len(errs))
		}
		return nil
	}

	c.log.Errorf("❌ DESCRIPTOR POST: Upload failed - insufficient successes (%d/%d threshold)",
		successCount, threshold)
	return fmt.Errorf("failure to Post(%d) to Directory Authorities: insufficient successes (%d/%d), errors: %v",
		epoch, successCount, threshold, errs)
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
func (c *Client) GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	c.log.Noticef("Get: Starting consensus fetch for epoch %d from %d authorities", epoch, len(c.cfg.Authorities))

	// Generate a random keypair to use for the link authentication.
	_, linkKey, err := c.cfg.KEMScheme.GenerateKeyPair()
	if err != nil {
		c.log.Errorf("Get: Failed to generate link key for epoch %d: %v", epoch, err)
		return nil, nil, err
	}
	c.log.Debugf("Get: Generated link key for epoch %d", epoch)

	// permute the order the client tries Authorities
	r := rand.NewMath()
	idxs := r.Perm(len(c.cfg.Authorities))
	c.log.Debugf("Get: Randomized authority order for epoch %d: %v", epoch, idxs)

	// Collect detailed error information from each peer
	var peerErrors []error
	attemptCount := 0

	for _, idx := range idxs {
		attemptCount++
		auth := c.cfg.Authorities[idx]
		c.log.Debugf("Get: Attempt %d/%d - trying authority %s for epoch %d", attemptCount, len(c.cfg.Authorities), auth.Identifier, epoch)

		ctx, cancelFn := context.WithCancel(ctx)
		resp, err := c.pool.fetchConsensus(auth, ctx, linkKey, epoch)
		defer cancelFn()
		if err != nil {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): fetchConsensus failed: %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				kpcommon.TruncatePEMForLogging(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				err)
			c.log.Errorf("Get: Attempt %d/%d failed - fetchConsensus from authority %s for epoch %d failed: %s", attemptCount, len(c.cfg.Authorities), auth.Identifier, epoch, err)
			peerErrors = append(peerErrors, peerErr)
			continue
		}
		c.log.Debugf("Get: Attempt %d/%d - successfully fetched response from authority %s for epoch %d", attemptCount, len(c.cfg.Authorities), auth.Identifier, epoch)

		// Parse the consensus command.
		c.log.Debugf("Get: Parsing consensus response from authority %s for epoch %d", auth.Identifier, epoch)
		r, ok := resp.(*commands.Consensus)
		if !ok {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): unexpected reply: %T",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				resp)
			c.log.Errorf("Get: Authority %s returned unexpected reply type %T for epoch %d", auth.Identifier, resp, epoch)
			peerErrors = append(peerErrors, peerErr)
			continue
		}
		c.log.Debugf("Get: Successfully parsed consensus response from authority %s for epoch %d, error code: %s", auth.Identifier, epoch, getErrorToString(r.ErrorCode))

		switch r.ErrorCode {
		case commands.ConsensusOk:
			c.log.Debugf("Get: Authority %s returned ConsensusOk for epoch %d", auth.Identifier, epoch)
		case commands.ConsensusGone:
			// TODO: we should never try to fetch this again?
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): consensus gone",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)))
			c.log.Errorf("Get: Authority %s returned ConsensusGone for epoch %d - document will never be available", auth.Identifier, epoch)
			peerErrors = append(peerErrors, peerErr)
			continue
		case commands.ConsensusNotFound:
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): consensus not found",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)))
			c.log.Errorf("Get: Authority %s returned ConsensusNotFound for epoch %d - document not yet available", auth.Identifier, epoch)
			peerErrors = append(peerErrors, peerErr)
			continue
		default:
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): rejected with %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				getErrorToString(r.ErrorCode))
			c.log.Errorf("Get: Authority %s rejected request for epoch %d with error: %v", auth.Identifier, epoch, getErrorToString(r.ErrorCode))
			peerErrors = append(peerErrors, peerErr)
			continue
		}

		// Verify document signatures.
		c.log.Debugf("Get: Verifying threshold signatures from authority %s for epoch %d (threshold: %d)", auth.Identifier, epoch, c.threshold)
		doc := &pki.Document{}
		_, good, bad, err := cert.VerifyThreshold(c.verifiers, c.threshold, r.Payload)
		if err != nil {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): signature verification failed: %d good, %d bad: %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				kpcommon.TruncatePEMForLogging(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				len(good), len(bad), err)
			c.log.Errorf("Get: Signature verification failed from authority %s for epoch %d: %d good signatures, %d bad signatures: %v", auth.Identifier, epoch, len(good), len(bad), err)
			peerErrors = append(peerErrors, peerErr)
			continue
		}
		c.log.Debugf("Get: Signature verification passed from authority %s for epoch %d: %d good, %d bad signatures", auth.Identifier, epoch, len(good), len(bad))

		if len(good) == len(c.cfg.Authorities) {
			c.log.Noticef("Get: Received fully signed consensus document from authority %s for epoch %d", auth.Identifier, epoch)
		} else {
			c.log.Noticef("Get: Received consensus document from authority %s for epoch %d with %d of %d signatures", auth.Identifier, epoch, len(good), len(c.cfg.Authorities))
			for _, authConfig := range c.cfg.Authorities {
				for _, badauth := range bad {
					if badauth == authConfig.IdentityPublicKey {
						c.log.Warningf("Get: Missing or invalid signature from authority %s for epoch %d", authConfig.Identifier, epoch)
						break
					}
				}
			}
		}

		c.log.Debugf("Get: Parsing consensus document from authority %s for epoch %d", auth.Identifier, epoch)
		doc, err = pki.ParseDocument(r.Payload)
		if err != nil {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): invalid consensus document: %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				err)
			c.log.Errorf("Get: Failed to parse consensus document from authority %s for epoch %d: %s", auth.Identifier, epoch, err)
			peerErrors = append(peerErrors, peerErr)
			continue
		}
		c.log.Debugf("Get: Successfully parsed consensus document from authority %s for epoch %d", auth.Identifier, epoch)

		c.log.Debugf("Get: Validating document structure from authority %s for epoch %d", auth.Identifier, epoch)
		err = pki.IsDocumentWellFormed(doc, c.verifiers)
		if err != nil {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): document not well formed: %v",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				err)
			c.log.Errorf("Get: Document validation failed from authority %s for epoch %d: %s", auth.Identifier, epoch, err)
			peerErrors = append(peerErrors, peerErr)
			continue
		}
		c.log.Debugf("Get: Document structure validation passed from authority %s for epoch %d", auth.Identifier, epoch)

		if doc.Epoch != epoch {
			peerErr := fmt.Errorf("peer %s (%s, identity=%s, link=%s): wrong epoch: got %d, expected %d",
				auth.Identifier,
				strings.Join(auth.Addresses, ","),
				strings.TrimSpace(signpem.ToPublicPEMString(auth.IdentityPublicKey)),
				strings.TrimSpace(kempem.ToPublicPEMString(auth.LinkPublicKey)),
				doc.Epoch, epoch)
			c.log.Errorf("Get: EPOCH MISMATCH from authority %s: got epoch %d, expected %d", auth.Identifier, doc.Epoch, epoch)
			peerErrors = append(peerErrors, peerErr)
			continue
		}
		c.log.Debugf("Get: Epoch validation passed from authority %s: document epoch %d matches requested epoch %d", auth.Identifier, doc.Epoch, epoch)

		c.log.Noticef("Get: SUCCESS! Retrieved valid consensus document from authority %s for epoch %d", auth.Identifier, epoch)
		c.log.Debugf("Get: Final consensus details - epoch: %d, genesis: %d, mix nodes: %d, gateways: %d, services: %d, replicas: %d",
			doc.Epoch, doc.GenesisEpoch, len(doc.Topology), len(doc.GatewayNodes), len(doc.ServiceNodes), len(doc.StorageReplicas))
		c.log.Debugf("Get: Consensus document from authority %s for epoch %d:\n%s", auth.Identifier, epoch, doc)
		return doc, r.Payload, nil
	}

	// All authorities failed, return detailed error information
	c.log.Errorf("Get: CRITICAL FAILURE - All %d authorities failed for epoch %d", len(c.cfg.Authorities), epoch)
	e, _, _ := epochtime.Now()
	if len(peerErrors) > 0 {
		for i, peerErr := range peerErrors {
			c.log.Errorf("Get: Authority %d failure: %s", i+1, peerErr.Error())
		}
		if epoch <= e {
			c.log.Errorf("Get: Failed to get consensus for past/current epoch %d (current: %d)", epoch, e)
			return nil, nil, fmt.Errorf("failed to get consensus document (epoch %d <= current %d): %v", epoch, e, peerErrors)
		} else {
			c.log.Errorf("Get: Failed to get consensus for future epoch %d (current: %d)", epoch, e)
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
