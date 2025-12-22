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
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/retry"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
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

// IsPeerValid authenticates the remote peer's credentials.
func (a *authorityAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	identityHash := hash.Sum256From(a.IdentityPublicKey)
	if !hmac.Equal(identityHash[:], creds.AdditionalData[:hash.HashSize]) {
		a.log.Warningf("voting/Client: IsPeerValid(): AD mismatch: %x != %x", identityHash[:], creds.AdditionalData[:hash.HashSize])
		return false
	}
	if !a.LinkPublicKey.Equal(creds.PublicKey) {
		a.log.Warningf("voting/Client: IsPeerValid(): Link Public Key mismatch")
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

	// Network timeouts (seconds)
	DialTimeoutSec      int
	HandshakeTimeoutSec int
	ResponseTimeoutSec  int

	// Retry configuration
	RetryMaxAttempts int
	RetryBaseDelay   time.Duration
	RetryMaxDelay    time.Duration
	RetryJitter      float64
}

func (cfg *Config) validate() error {
	if cfg.DialTimeoutSec == 0 {
		cfg.DialTimeoutSec = 30
	}
	if cfg.HandshakeTimeoutSec == 0 {
		cfg.HandshakeTimeoutSec = 180
	}
	if cfg.ResponseTimeoutSec == 0 {
		cfg.ResponseTimeoutSec = 90
	}

	if cfg.RetryMaxAttempts <= 0 {
		cfg.RetryMaxAttempts = retry.DefaultMaxAttempts
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = retry.DefaultBaseDelay
	}
	if cfg.RetryMaxDelay <= 0 {
		cfg.RetryMaxDelay = retry.DefaultMaxDelay
	}
	if cfg.RetryJitter <= 0 {
		cfg.RetryJitter = retry.DefaultJitter
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

type connector struct {
	cfg *Config
	log *logging.Logger
}

func newConnector(cfg *Config) *connector {
	return &connector{
		cfg: cfg,
		log: cfg.LogBackend.GetLogger("pki/voting/client/connector"),
	}
}

func (p *connector) initSession(ctx context.Context, linkKey kem.PrivateKey, signingKey sign.PublicKey, peer *config.Authority) (*connection, error) {
	var conn net.Conn
	var err error

	peerInfo := func() string {
		return fmt.Sprintf("peer %s (%s)", peer.Identifier, strings.Join(peer.Addresses, ","))
	}

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

	r := rand.NewMath()
	idxs := r.Perm(len(peer.Addresses))

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
			return nil, fmt.Errorf("%s: all connection attempts failed: %v", peerInfo(), lastErr)
		}
	}

	peerAuthenticator := &authorityAuthenticator{
		IdentityPublicKey: peer.IdentityPublicKey,
		LinkPublicKey:     peer.LinkPublicKey,
		log:               p.log,
	}

	var ad []byte
	if signingKey != nil {
		keyHash := hash.Sum256From(signingKey)
		ad = keyHash[:]
	}

	kemScheme := schemes.ByName(peer.WireKEMScheme)
	if kemScheme == nil {
		return nil, fmt.Errorf("%s: unsupported KEM scheme: %s", peerInfo(), peer.WireKEMScheme)
	}

	var pkiSignatureScheme sign.Scheme
	if peer.PKISignatureScheme != "" {
		pkiSignatureScheme = signSchemes.ByName(peer.PKISignatureScheme)
		if pkiSignatureScheme == nil {
			return nil, fmt.Errorf("%s: unsupported PKI signature scheme: %s", peerInfo(), peer.PKISignatureScheme)
		}
	}

	cfg := &wire.SessionConfig{
		KEMScheme:          kemScheme,
		PKISignatureScheme: pkiSignatureScheme,
		Geometry:           p.cfg.Geo,
		Authenticator:      peerAuthenticator,
		AdditionalData:     ad,
		AuthenticationKey:  linkKey,
		RandomReader:       rand.Reader,
	}
	s, err := wire.NewPKISession(cfg, true)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create PKI session: %v", peerInfo(), err)
	}

	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	handshakeStart := time.Now()
	if err = s.Initialize(conn); err != nil {
		conn.Close()
		// Add peer name context to the error if it's a HandshakeError
		if he, ok := wire.GetHandshakeError(err); ok {
			he.WithPeerName(peer.Identifier)
		}
		// Log detailed debug info (contains IPs, keys, peer name) at debug level only
		p.log.Debugf("%s: handshake failure details:\n%s", peerInfo(), wire.GetDebugError(err))
		return nil, err
	}
	p.log.Debugf("%s: Handshake completed in %v", peerInfo(), time.Since(handshakeStart))

	conn.SetDeadline(time.Now().Add(responseTimeout))

	return &connection{conn: conn, session: s}, nil
}

func (p *connector) initSessionWithRetry(ctx context.Context, linkKey kem.PrivateKey, signingKey sign.PublicKey, peer *config.Authority) (*connection, error) {
	var lastErr error
	for attempt := 0; attempt <= p.cfg.RetryMaxAttempts; attempt++ {
		if attempt > 0 {
			delay := retry.Delay(p.cfg.RetryBaseDelay, p.cfg.RetryMaxDelay, p.cfg.RetryJitter, attempt-1)
			p.log.Debugf("authority %s: retry %d/%d after %v", peer.Identifier, attempt, p.cfg.RetryMaxAttempts, delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		conn, err := p.initSession(ctx, linkKey, signingKey, peer)
		if err == nil {
			if attempt > 0 {
				p.log.Noticef("authority %s: connected after %d retries", peer.Identifier, attempt)
			}
			return conn, nil
		}
		lastErr = err
		if !retry.IsTransientError(err) {
			return nil, err
		}
		p.log.Warningf("authority %s: attempt %d failed: %v", peer.Identifier, attempt+1, err)
	}
	return nil, lastErr
}

func (p *connector) roundTrip(s *wire.Session, cmd commands.Command) (commands.Command, error) {
	sendStart := time.Now()
	if err := s.SendCommand(cmd); err != nil {
		return nil, err
	}
	p.log.Debugf("Sent %s in %v", cmd, time.Since(sendStart))
	return s.RecvCommand()
}

type PeerResponse struct {
	Peer     *config.Authority
	Response commands.Command
	Error    error
}

func (p *connector) allPeersRoundTrip(ctx context.Context, linkKey kem.PrivateKey, signingKey sign.PublicKey, cmd commands.Command) ([]PeerResponse, error) {
	p.log.Debugf("allPeersRoundTrip: contacting %d authorities in parallel", len(p.cfg.Authorities))

	responseCh := make(chan PeerResponse, len(p.cfg.Authorities))
	var w worker.Worker

	for _, peer := range p.cfg.Authorities {
		peer := peer
		w.Go(func() {
			ictx, cancelFn := context.WithCancel(ctx)
			defer cancelFn()
			conn, err := p.initSessionWithRetry(ictx, linkKey, signingKey, peer)
			if err != nil {
				p.log.Errorf("allPeersRoundTrip: %s: %v", peer.Identifier, err)
				responseCh <- PeerResponse{Peer: peer, Error: err}
				return
			}
			defer conn.conn.Close()

			resp, err := p.roundTrip(conn.session, cmd)
			if err != nil {
				p.log.Errorf("allPeersRoundTrip: %s round trip failed: %v", peer.Identifier, err)
				responseCh <- PeerResponse{Peer: peer, Error: err}
				return
			}
			responseCh <- PeerResponse{Peer: peer, Response: resp}
		})
	}

	w.Wait()
	close(responseCh)

	peerResponses := []PeerResponse{}
	for resp := range responseCh {
		peerResponses = append(peerResponses, resp)
	}

	if len(peerResponses) == 0 {
		return nil, errors.New("allPeersRoundTrip: got zero responses")
	}
	return peerResponses, nil
}

func (p *connector) fetchConsensus(auth *config.Authority, ctx context.Context, linkKey kem.PrivateKey, epoch uint64) (commands.Command, error) {
	if len(p.cfg.Authorities) == 0 {
		return nil, errors.New("zero Authorities specified")
	}

	conn, err := p.initSessionWithRetry(ctx, linkKey, nil, auth)
	if err != nil {
		return nil, fmt.Errorf("peer %s: connection failed: %v", auth.Identifier, err)
	}
	defer conn.conn.Close()

	cmd := &commands.GetConsensus{
		Epoch:              epoch,
		Cmds:               commands.NewPKICommands(p.cfg.PKISignatureScheme),
		MixnetTransmission: false,
	}

	resp, err := p.roundTrip(conn.session, cmd)
	if err != nil {
		return nil, fmt.Errorf("peer %s: round trip failed: %v", auth.Identifier, err)
	}

	r, ok := resp.(*commands.Consensus)
	if !ok {
		return nil, fmt.Errorf("peer %s: invalid response type: %T", auth.Identifier, resp)
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

	cmd := &commands.PostDescriptor{Epoch: epoch, Payload: []byte(signed)}
	peerResponses, err := c.pool.allPeersRoundTrip(ctx, c.cfg.LinkKey, signingPublicKey, cmd)
	if err != nil {
		return err
	}

	errs := []error{}
	successCount := 0

	for _, peerResp := range peerResponses {
		if peerResp.Error != nil {
			errs = append(errs, fmt.Errorf("%s: %v", peerResp.Peer.Identifier, peerResp.Error))
			continue
		}

		r, ok := peerResp.Response.(*commands.PostDescriptorStatus)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: unexpected reply: %T", peerResp.Peer.Identifier, peerResp.Response))
			continue
		}

		switch r.ErrorCode {
		case commands.DescriptorOk:
			successCount++
		default:
			errs = append(errs, fmt.Errorf("%s: %s", peerResp.Peer.Identifier, commands.DescriptorErrorToString(r.ErrorCode)))
		}
	}

	threshold := (len(peerResponses) / 2) + 1
	if successCount >= threshold {
		return nil
	}

	return fmt.Errorf("Post(%d) failed: %d/%d successes, errors: %v", epoch, successCount, threshold, errs)
}

// PostReplica posts the replica descriptor.
func (c *Client) PostReplica(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.ReplicaDescriptor) error {
	if err := pki.IsReplicaDescriptorWellFormed(d, epoch); err != nil {
		return err
	}

	signedUpload := &pki.SignedReplicaUpload{ReplicaDescriptor: d}
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

	cmd := &commands.PostReplicaDescriptor{Epoch: epoch, Payload: []byte(signed)}
	peerResponses, err := c.pool.allPeersRoundTrip(ctx, c.cfg.LinkKey, signingPublicKey, cmd)
	if err != nil {
		return err
	}

	errs := []error{}
	for _, peerResp := range peerResponses {
		if peerResp.Error != nil {
			errs = append(errs, peerResp.Error)
			continue
		}
		r, ok := peerResp.Response.(*commands.PostDescriptorStatus)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: unexpected reply", peerResp.Peer.Identifier))
			continue
		}
		if r.ErrorCode != commands.DescriptorOk {
			errs = append(errs, fmt.Errorf("%s: %s", peerResp.Peer.Identifier, commands.DescriptorErrorToString(r.ErrorCode)))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("PostReplica(%d) errors: %v", epoch, errs)
}

// GetPKIDocumentForEpoch returns the PKI document for the provided epoch.
func (c *Client) GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	// Generate a random keypair to use for the link authentication.
	_, linkKey, err := c.cfg.KEMScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	r := rand.NewMath()
	idxs := r.Perm(len(c.cfg.Authorities))

	for _, idx := range idxs {
		auth := c.cfg.Authorities[idx]
		resp, err := c.pool.fetchConsensus(auth, ctx, linkKey, epoch)
		if err != nil {
			c.log.Errorf("Get: %s: %v", auth.Identifier, err)
			continue
		}

		r, ok := resp.(*commands.Consensus)
		if !ok {
			continue
		}

		if r.ErrorCode != commands.ConsensusOk {
			continue
		}

		_, good, _, err := cert.VerifyThreshold(c.verifiers, c.threshold, r.Payload)
		if err != nil {
			c.log.Errorf("Get: %s: signature verification failed: %v", auth.Identifier, err)
			continue
		}

		doc, err := pki.ParseDocument(r.Payload)
		if err != nil {
			continue
		}

		if err = pki.IsDocumentWellFormed(doc, c.verifiers); err != nil {
			continue
		}

		if doc.Epoch != epoch {
			continue
		}

		c.log.Noticef("Get: retrieved valid consensus from %s for epoch %d (%d sigs)", auth.Identifier, epoch, len(good))
		return doc, r.Payload, nil
	}

	e, _, _ := epochtime.Now()
	if epoch <= e {
		return nil, nil, pki.ErrDocumentGone
	}
	return nil, nil, pki.ErrNoDocument
}

// Deserialize returns PKI document given the raw bytes.
func (c *Client) Deserialize(raw []byte) (*pki.Document, error) {
	_, _, _, err := cert.VerifyThreshold(c.verifiers, c.threshold, raw)
	if err != nil {
		return nil, err
	}
	return pki.ParseDocument(raw)
}

// New constructs a new pki.Client instance.
func New(cfg *Config) (pki.Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	c := &Client{
		cfg:  cfg,
		log:  cfg.LogBackend.GetLogger("pki/voting/Client"),
		pool: newConnector(cfg),
	}
	c.verifiers = make([]sign.PublicKey, 0, len(cfg.Authorities))
	for _, auth := range cfg.Authorities {
		c.verifiers = append(c.verifiers, auth.IdentityPublicKey)
	}
	c.threshold = len(c.verifiers)/2 + 1
	return c, nil
}
