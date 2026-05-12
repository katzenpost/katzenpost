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
	"sort"
	"strconv"
	"strings"
	"sync"
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

// authorityAuthenticator implements the PeerAuthenticator interface.
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

	// PKISignatureScheme specifies the cryptographic signature scheme.
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

	// Network timeouts, in seconds.
	DialTimeoutSec      int
	HandshakeTimeoutSec int
	ResponseTimeoutSec  int

	// Retry configuration.
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
		cfg.HandshakeTimeoutSec = 60
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
		if v.LinkPublicKey.PublicKey == nil {
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

func (p *connector) initSession(
	ctx context.Context,
	linkKey kem.PrivateKey,
	signingKey sign.PublicKey,
	peer *config.Authority,
	timeoutOverride time.Duration,
) (*connection, error) {
	var conn net.Conn
	var err error
	var connectedURL string

	peerInfo := func() string {
		return fmt.Sprintf("peer %s (%s)", peer.Identifier, strings.Join(peer.Addresses, ","))
	}

	dialTimeout := time.Duration(p.cfg.DialTimeoutSec) * time.Second
	handshakeTimeout := time.Duration(p.cfg.HandshakeTimeoutSec) * time.Second
	responseTimeout := time.Duration(p.cfg.ResponseTimeoutSec) * time.Second
	if timeoutOverride > 0 {
		dialTimeout = timeoutOverride
		handshakeTimeout = timeoutOverride
		responseTimeout = timeoutOverride
	}

	p.log.Debugf("Client timeouts: dial=%v, handshake=%v, response=%v", dialTimeout, handshakeTimeout, responseTimeout)

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
		cancelFn()
		if err == nil {
			connectedURL = peer.Addresses[idx]
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
		if conn != nil {
			conn.Close()
		}
		return nil, fmt.Errorf("%s: failed to create PKI session: %v", peerInfo(), err)
	}

	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	handshakeStart := time.Now()
	if err = s.Initialize(conn); err != nil {
		handshakeElapsed := time.Since(handshakeStart)

		localAddr := ""
		if conn.LocalAddr() != nil {
			localAddr = conn.LocalAddr().String()
		}

		remoteAddr := ""
		if conn.RemoteAddr() != nil {
			remoteAddr = conn.RemoteAddr().String()
		}

		conn.Close()

		if he, ok := wire.GetHandshakeError(err); ok {
			he.WithPeerName(peer.Identifier)
		}

		// Log detailed debug info, including IP addresses and key material, at
		// debug level only.
		p.log.Debugf("%s: handshake failure details:\n%s", peerInfo(), wire.GetDebugError(err))

		return nil, fmt.Errorf(
			"%s: handshake failed via %s local=%s remote=%s after %v timeout=%v: %w",
			peerInfo(),
			connectedURL,
			localAddr,
			remoteAddr,
			handshakeElapsed,
			handshakeTimeout,
			err,
		)
	}

	p.log.Debugf("%s: Handshake completed in %v", peerInfo(), time.Since(handshakeStart))
	conn.SetDeadline(time.Now().Add(responseTimeout))
	return &connection{conn: conn, session: s}, nil
}

func (p *connector) initSessionWithRetry(
	ctx context.Context,
	linkKey kem.PrivateKey,
	signingKey sign.PublicKey,
	peer *config.Authority,
) (*connection, error) {
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

		conn, err := p.initSession(ctx, linkKey, signingKey, peer, 0)
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

func (p *connector) allPeersRoundTrip(
	ctx context.Context,
	linkKey kem.PrivateKey,
	signingKey sign.PublicKey,
	cmd commands.Command,
) ([]PeerResponse, error) {
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

type postAttemptKind int

const (
	postAttemptTransport postAttemptKind = iota
	postAttemptAccepted
	postAttemptConflict
	postAttemptSemantic
)

type postAttemptResult struct {
	peer       *config.Authority
	round      int
	kind       postAttemptKind
	errorCode  uint8
	err        error
	elapsed    time.Duration
	statusText string
}

type postPeerState struct {
	peer          *config.Authority
	accepted      bool
	conflict      bool
	lastErr       error
	attempts      int
	nextAttemptAt time.Time
}

type postSummary struct {
	successes           int
	conflicts           int
	transportErrors     int
	semanticErrors      int
	acceptedAuthorities []string
	conflictAuthorities []string
	errs                []error
}

func postInitialTimeout(round int) time.Duration {
	// Start at 10% of the legacy one-minute handshake timeout, then approach
	// the old maximum on later best-effort completion rounds.
	switch {
	case round <= 0:
		return 6 * time.Second
	case round == 1:
		return 12 * time.Second
	case round == 2:
		return 24 * time.Second
	case round == 3:
		return 48 * time.Second
	default:
		return 60 * time.Second
	}
}

func descriptorPostRetryDelay(cfg *Config, attempts int) time.Duration {
	// Descriptor POST completion rounds need a real per-authority sleep timer.
	//
	// The generic retry configuration can be tuned very low for unit tests or
	// other call paths. That is fine for initSessionWithRetry(), but descriptor
	// fanout is an upload-window operation: when an authority has a closed port
	// or times out during handshake finalization, immediately rescheduling it a
	// few milliseconds later causes noisy retry storms and can starve useful
	// attempts to other dirauths. Keep trying the failed dirauth, but pace each
	// dirauth independently.
	if attempts < 1 {
		attempts = 1
	}

	base := cfg.RetryBaseDelay
	if base < 2*time.Second {
		base = 2 * time.Second
	}

	maxDelay := cfg.RetryMaxDelay
	if maxDelay < 20*time.Second {
		maxDelay = 20 * time.Second
	}
	if maxDelay < base {
		maxDelay = base
	}

	delay := base
	for i := 1; i < attempts; i++ {
		if delay >= maxDelay/2 {
			return maxDelay
		}
		delay *= 2
	}

	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

func descriptorStatusText(code uint8) string {
	return commands.DescriptorErrorToString(code)
}

func descriptorStatusIsOK(code uint8) bool {
	return code == commands.DescriptorOk || strings.EqualFold(descriptorStatusText(code), "Ok")
}

func descriptorStatusIsConflict(code uint8) bool {
	return strings.EqualFold(descriptorStatusText(code), "Conflict")
}

func (p *connector) postAuthorityOnce(
	ctx context.Context,
	linkKey kem.PrivateKey,
	signingKey sign.PublicKey,
	cmd commands.Command,
	peer *config.Authority,
	round int,
	timeout time.Duration,
) postAttemptResult {
	start := time.Now()
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := p.initSession(attemptCtx, linkKey, signingKey, peer, timeout)
	if err != nil {
		elapsed := time.Since(start)
		p.log.Warningf(
			"post authority %s: attempt failed after %v timeout=%v: %v",
			peer.Identifier,
			elapsed,
			timeout,
			err,
		)
		return postAttemptResult{
			peer:    peer,
			round:   round,
			kind:    postAttemptTransport,
			err:     err,
			elapsed: elapsed,
		}
	}
	defer conn.conn.Close()

	resp, err := p.roundTrip(conn.session, cmd)
	if err != nil {
		elapsed := time.Since(start)
		p.log.Warningf(
			"post authority %s: round trip failed after %v timeout=%v: %v",
			peer.Identifier,
			elapsed,
			timeout,
			err,
		)
		return postAttemptResult{
			peer:    peer,
			round:   round,
			kind:    postAttemptTransport,
			err:     err,
			elapsed: elapsed,
		}
	}

	status, ok := resp.(*commands.PostDescriptorStatus)
	if !ok {
		replicaStatus, replicaOK := resp.(*commands.PostReplicaDescriptorStatus)
		if !replicaOK {
			elapsed := time.Since(start)
			err := fmt.Errorf("unexpected reply: %T", resp)
			return postAttemptResult{
				peer:    peer,
				round:   round,
				kind:    postAttemptSemantic,
				err:     err,
				elapsed: elapsed,
			}
		}

		status = &commands.PostDescriptorStatus{
			ErrorCode: replicaStatus.ErrorCode,
		}
	}

	elapsed := time.Since(start)
	statusText := descriptorStatusText(status.ErrorCode)

	switch {
	case descriptorStatusIsOK(status.ErrorCode):
		return postAttemptResult{
			peer:       peer,
			round:      round,
			kind:       postAttemptAccepted,
			errorCode:  status.ErrorCode,
			elapsed:    elapsed,
			statusText: statusText,
		}
	case descriptorStatusIsConflict(status.ErrorCode):
		return postAttemptResult{
			peer:       peer,
			round:      round,
			kind:       postAttemptConflict,
			errorCode:  status.ErrorCode,
			err:        fmt.Errorf("%s", statusText),
			elapsed:    elapsed,
			statusText: statusText,
		}
	default:
		return postAttemptResult{
			peer:       peer,
			round:      round,
			kind:       postAttemptSemantic,
			errorCode:  status.ErrorCode,
			err:        fmt.Errorf("%s", statusText),
			elapsed:    elapsed,
			statusText: statusText,
		}
	}
}

func (p *connector) runPostRound(
	ctx context.Context,
	linkKey kem.PrivateKey,
	signingKey sign.PublicKey,
	cmd commands.Command,
	states []*postPeerState,
) []postAttemptResult {
	resultsCh := make(chan postAttemptResult, len(states))
	var w worker.Worker

	for _, state := range states {
		state := state
		timeout := clampTimeoutToContext(ctx, postInitialTimeout(state.attempts))
		w.Go(func() {
			resultsCh <- p.postAuthorityOnce(ctx, linkKey, signingKey, cmd, state.peer, state.attempts, timeout)
		})
	}

	w.Wait()
	close(resultsCh)

	results := make([]postAttemptResult, 0, len(states))
	for result := range resultsCh {
		results = append(results, result)
	}

	return results
}

func updatePostSummary(states map[string]*postPeerState) postSummary {
	var summary postSummary

	for _, state := range states {
		switch {
		case state.accepted:
			summary.successes++
			summary.acceptedAuthorities = append(summary.acceptedAuthorities, state.peer.Identifier)

		case state.conflict:
			summary.conflicts++
			summary.conflictAuthorities = append(summary.conflictAuthorities, state.peer.Identifier)
			if state.lastErr != nil {
				summary.errs = append(
					summary.errs,
					fmt.Errorf("%s: %v", strconv.QuoteToASCII(state.peer.Identifier), state.lastErr),
				)
			}

		case state.lastErr != nil:
			msg := state.lastErr.Error()
			if strings.Contains(msg, "unexpected reply") ||
				strings.EqualFold(msg, "Ok") ||
				strings.Contains(msg, "Descriptor") {
				summary.semanticErrors++
			} else {
				summary.transportErrors++
			}
			summary.errs = append(
				summary.errs,
				fmt.Errorf("%s: %v", strconv.QuoteToASCII(state.peer.Identifier), state.lastErr),
			)
		}
	}

	sort.Strings(summary.acceptedAuthorities)
	sort.Strings(summary.conflictAuthorities)

	return summary
}

func peersNeedingCompletion(states map[string]*postPeerState) []*config.Authority {
	peers := []*config.Authority{}

	for _, state := range states {
		if state.accepted {
			continue
		}
		if state.conflict {
			continue
		}
		peers = append(peers, state.peer)
	}

	return peers
}

func postStatesReadyForCompletion(states map[string]*postPeerState, now time.Time) []*postPeerState {
	ready := []*postPeerState{}

	for _, state := range states {
		if state.accepted {
			continue
		}
		if state.conflict {
			continue
		}
		if state.nextAttemptAt.IsZero() || !state.nextAttemptAt.After(now) {
			ready = append(ready, state)
		}
	}

	return ready
}

func nextPostAttemptAt(states map[string]*postPeerState) (time.Time, bool) {
	var next time.Time

	for _, state := range states {
		if state.accepted {
			continue
		}
		if state.conflict {
			continue
		}
		if state.nextAttemptAt.IsZero() {
			return time.Now(), true
		}
		if next.IsZero() || state.nextAttemptAt.Before(next) {
			next = state.nextAttemptAt
		}
	}

	if next.IsZero() {
		return time.Time{}, false
	}
	return next, true
}

func ctxStillOpen(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	default:
		return true
	}
}

func remainingContextBudget(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return time.Until(deadline)
}

func clampTimeoutToContext(ctx context.Context, timeout time.Duration) time.Duration {
	remaining := remainingContextBudget(ctx)
	if remaining <= 0 {
		return timeout
	}
	if remaining < timeout {
		return remaining
	}
	return timeout
}

func logPostAttemptResult(
	log *logging.Logger,
	epoch uint64,
	threshold int,
	roundLabel string,
	result postAttemptResult,
	summary postSummary,
	pending int,
) {
	switch result.kind {
	case postAttemptAccepted:
		log.Noticef(
			"Post(%d): %s accepted by %s after %v successes=%d/%d conflicts=%d pending=%d",
			epoch,
			roundLabel,
			strconv.QuoteToASCII(result.peer.Identifier),
			result.elapsed,
			summary.successes,
			threshold,
			summary.conflicts,
			pending,
		)
	case postAttemptConflict:
		log.Warningf(
			"Post(%d): %s conflict from %s after %v successes=%d/%d conflicts=%d/%d pending=%d",
			epoch,
			roundLabel,
			strconv.QuoteToASCII(result.peer.Identifier),
			result.elapsed,
			summary.successes,
			threshold,
			summary.conflicts,
			threshold,
			pending,
		)
	case postAttemptSemantic:
		log.Warningf(
			"Post(%d): %s semantic failure from %s after %v: %v pending=%d",
			epoch,
			roundLabel,
			strconv.QuoteToASCII(result.peer.Identifier),
			result.elapsed,
			result.err,
			pending,
		)
	case postAttemptTransport:
		log.Warningf(
			"Post(%d): %s transport failed for %s after %v: %v pending=%d",
			epoch,
			roundLabel,
			strconv.QuoteToASCII(result.peer.Identifier),
			result.elapsed,
			result.err,
			pending,
		)
	}
}

func (p *connector) postDescriptorWithCompletionRounds(
	ctx context.Context,
	epoch uint64,
	linkKey kem.PrivateKey,
	signingKey sign.PublicKey,
	cmd commands.Command,
) postSummary {
	threshold := (len(p.cfg.Authorities) / 2) + 1

	states := make(map[string]*postPeerState, len(p.cfg.Authorities))
	for _, peer := range p.cfg.Authorities {
		states[peer.Identifier] = &postPeerState{peer: peer}
	}

	p.log.Noticef(
		"Post(%d): starting descriptor upload fanout authorities=%d threshold=%d",
		epoch,
		len(p.cfg.Authorities),
		threshold,
	)

	round := 0
	quorumReachedLogged := false

	for ctxStillOpen(ctx) {
		summary := updatePostSummary(states)
		targets := peersNeedingCompletion(states)

		if len(targets) == 0 {
			p.log.Noticef(
				"Post(%d): descriptor upload complete successes=%d/%d conflicts=%d/%d transport_errors=%d semantic_errors=%d",
				epoch,
				summary.successes,
				threshold,
				summary.conflicts,
				threshold,
				summary.transportErrors,
				summary.semanticErrors,
			)
			return summary
		}

		now := time.Now()
		readyStates := postStatesReadyForCompletion(states, now)
		if len(readyStates) == 0 {
			nextAttemptAt, ok := nextPostAttemptAt(states)
			if !ok {
				break
			}

			delay := time.Until(nextAttemptAt)
			if delay < 0 {
				delay = 0
			}

			remaining := remainingContextBudget(ctx)
			if remaining > 0 && delay > remaining {
				break
			}

			p.log.Noticef(
				"Post(%d): waiting for next per-authority retry delay=%v next_attempt_at=%v pending=%d remaining_budget=%v",
				epoch,
				delay,
				nextAttemptAt,
				len(targets),
				remaining,
			)

			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return updatePostSummary(states)
			}
			continue
		}

		roundLabel := "first-attempt"
		if round > 0 {
			roundLabel = fmt.Sprintf("completion-round-%d", round)
			p.log.Noticef(
				"Post(%d): %s retrying ready incomplete authorities ready=%d pending=%d remaining_budget=%v",
				epoch,
				roundLabel,
				len(readyStates),
				len(targets),
				remainingContextBudget(ctx),
			)
		}

		results := p.runPostRound(ctx, linkKey, signingKey, cmd, readyStates)
		for _, result := range results {
			state := states[result.peer.Identifier]
			if state == nil {
				continue
			}

			switch result.kind {
			case postAttemptAccepted:
				state.accepted = true
				state.lastErr = nil
				state.nextAttemptAt = time.Time{}

			case postAttemptConflict:
				state.conflict = true
				state.lastErr = result.err
				state.nextAttemptAt = time.Time{}

			case postAttemptSemantic, postAttemptTransport:
				state.lastErr = result.err
				state.attempts++

				delay := descriptorPostRetryDelay(p.cfg, state.attempts)
				state.nextAttemptAt = time.Now().Add(delay)

				p.log.Noticef(
					"Post(%d): %s scheduling retry for authority %s attempt=%d delay=%v next_attempt_at=%v",
					epoch,
					roundLabel,
					strconv.QuoteToASCII(state.peer.Identifier),
					state.attempts+1,
					delay,
					state.nextAttemptAt,
				)
			}

			summary = updatePostSummary(states)
			pending := len(peersNeedingCompletion(states))
			logPostAttemptResult(p.log, epoch, threshold, roundLabel, result, summary, pending)

			if summary.successes >= threshold && !quorumReachedLogged {
				quorumReachedLogged = true
				p.log.Noticef(
					"Post(%d): quorum reached successes=%d/%d; continuing best-effort per-authority completion retries while upload window remains open",
					epoch,
					summary.successes,
					threshold,
				)
			}

			if summary.conflicts >= threshold {
				p.log.Warningf(
					"Post(%d): conflict quorum reached conflicts=%d/%d successes=%d/%d transport_errors=%d semantic_errors=%d",
					epoch,
					summary.conflicts,
					threshold,
					summary.successes,
					threshold,
					summary.transportErrors,
					summary.semanticErrors,
				)
				return summary
			}
		}

		summary = updatePostSummary(states)
		if summary.successes < threshold {
			pending := len(peersNeedingCompletion(states))
			if summary.successes+pending < threshold {
				p.log.Warningf(
					"Post(%d): quorum impossible successes=%d/%d conflicts=%d/%d pending=%d",
					epoch,
					summary.successes,
					threshold,
					summary.conflicts,
					threshold,
					pending,
				)
				return summary
			}
		}

		round++

		// If the caller did not provide a deadline, do not spin forever.
		// The server PKI worker should provide an upload-window context deadline;
		// this fallback preserves safety for tests and unusual callers.
		if _, ok := ctx.Deadline(); !ok && round > 3 {
			p.log.Warningf("Post(%d): no context deadline; stopping completion rounds after %d rounds", epoch, round)
			break
		}
	}

	summary := updatePostSummary(states)
	p.log.Noticef(
		"Post(%d): descriptor upload fanout stopped successes=%d/%d conflicts=%d/%d transport_errors=%d semantic_errors=%d",
		epoch,
		summary.successes,
		threshold,
		summary.conflicts,
		threshold,
		summary.transportErrors,
		summary.semanticErrors,
	)
	return summary
}

func (p *connector) fetchConsensus(
	auth *config.Authority,
	ctx context.Context,
	linkKey kem.PrivateKey,
	epoch uint64,
) (commands.Command, error) {
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

	lastPostReplicaMu                  sync.Mutex
	lastPostReplicaEpoch               uint64
	lastPostReplicaAcceptedAuthorities []string
	lastPostReplicaConflictAuthorities []string
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func (c *Client) rememberLastPostReplicaSummary(epoch uint64, summary postSummary) {
	c.lastPostReplicaMu.Lock()
	defer c.lastPostReplicaMu.Unlock()

	c.lastPostReplicaEpoch = epoch
	c.lastPostReplicaAcceptedAuthorities = cloneStrings(summary.acceptedAuthorities)
	c.lastPostReplicaConflictAuthorities = cloneStrings(summary.conflictAuthorities)
}

// LastPostReplicaAcceptedAuthorities returns the authorities that accepted the
// most recent PostReplica call for the requested epoch.
func (c *Client) LastPostReplicaAcceptedAuthorities(epoch uint64) []string {
	c.lastPostReplicaMu.Lock()
	defer c.lastPostReplicaMu.Unlock()

	if c.lastPostReplicaEpoch != epoch {
		return nil
	}
	return cloneStrings(c.lastPostReplicaAcceptedAuthorities)
}

// LastPostReplicaConflictAuthorities returns the authorities that reported a
// descriptor conflict during the most recent PostReplica call for the requested
// epoch.
func (c *Client) LastPostReplicaConflictAuthorities(epoch uint64) []string {
	c.lastPostReplicaMu.Lock()
	defer c.lastPostReplicaMu.Unlock()

	if c.lastPostReplicaEpoch != epoch {
		return nil
	}
	return cloneStrings(c.lastPostReplicaConflictAuthorities)
}

// Post posts the node's descriptor to the PKI for the provided epoch.
func (c *Client) Post(
	ctx context.Context,
	epoch uint64,
	signingPrivateKey sign.PrivateKey,
	signingPublicKey sign.PublicKey,
	d *pki.MixDescriptor,
	loopstats *loops.LoopStats,
) error {
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

	cmd := &commands.PostDescriptor{
		Epoch:   epoch,
		Payload: []byte(signed),
	}

	summary := c.pool.postDescriptorWithCompletionRounds(ctx, epoch, c.cfg.LinkKey, signingPublicKey, cmd)
	threshold := (len(c.cfg.Authorities) / 2) + 1

	if summary.successes >= threshold {
		if len(summary.errs) > 0 {
			c.log.Warningf(
				"Post(%d): quorum succeeded with non-fatal authority errors: successes=%d/%d conflicts=%d/%d transport_errors=%d semantic_errors=%d errors=%v",
				epoch,
				summary.successes,
				threshold,
				summary.conflicts,
				threshold,
				summary.transportErrors,
				summary.semanticErrors,
				summary.errs,
			)
		}
		return nil
	}

	if summary.conflicts >= threshold {
		c.log.Warningf(
			"Post(%d): conflict quorum for descriptor upload: successes=%d/%d conflicts=%d/%d transport_errors=%d semantic_errors=%d errors=%v",
			epoch,
			summary.successes,
			threshold,
			summary.conflicts,
			threshold,
			summary.transportErrors,
			summary.semanticErrors,
			summary.errs,
		)
		return pki.ErrInvalidPostEpoch
	}

	return fmt.Errorf(
		"Post(%d) failed: %d/%d successes, %d/%d conflicts, transport_errors=%d semantic_errors=%d, errors: %v",
		epoch,
		summary.successes,
		threshold,
		summary.conflicts,
		threshold,
		summary.transportErrors,
		summary.semanticErrors,
		summary.errs,
	)
}

// PostReplica posts the replica descriptor.
func (c *Client) PostReplica(
	ctx context.Context,
	epoch uint64,
	signingPrivateKey sign.PrivateKey,
	signingPublicKey sign.PublicKey,
	d *pki.ReplicaDescriptor,
) error {
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

	cmd := &commands.PostReplicaDescriptor{
		Epoch:   epoch,
		Payload: []byte(signed),
	}

	summary := c.pool.postDescriptorWithCompletionRounds(ctx, epoch, c.cfg.LinkKey, signingPublicKey, cmd)
	threshold := (len(c.cfg.Authorities) / 2) + 1

	if summary.successes >= threshold {
		c.rememberLastPostReplicaSummary(epoch, summary)

		acceptedAuthorities := make([]string, 0, len(summary.acceptedAuthorities))
		for _, authority := range summary.acceptedAuthorities {
			acceptedAuthorities = append(acceptedAuthorities, strconv.QuoteToASCII(authority))
		}

		conflictAuthorities := make([]string, 0, len(summary.conflictAuthorities))
		for _, authority := range summary.conflictAuthorities {
			conflictAuthorities = append(conflictAuthorities, strconv.QuoteToASCII(authority))
		}

		c.log.Noticef(
			"PostReplica(%d): replica descriptor upload succeeded accepted_by=%v conflicts_from=%v successes=%d/%d conflicts=%d/%d transport_errors=%d semantic_errors=%d",
			epoch,
			acceptedAuthorities,
			conflictAuthorities,
			summary.successes,
			threshold,
			summary.conflicts,
			threshold,
			summary.transportErrors,
			summary.semanticErrors,
		)

		if len(summary.errs) > 0 {
			c.log.Warningf(
				"PostReplica(%d): quorum succeeded with non-fatal authority errors: successes=%d/%d conflicts=%d/%d transport_errors=%d semantic_errors=%d errors=%v",
				epoch,
				summary.successes,
				threshold,
				summary.conflicts,
				threshold,
				summary.transportErrors,
				summary.semanticErrors,
				summary.errs,
			)
		}
		return nil
	}

	if summary.conflicts >= threshold {
		c.rememberLastPostReplicaSummary(epoch, summary)
		c.log.Warningf(
			"PostReplica(%d): conflict quorum for replica descriptor upload: successes=%d/%d conflicts=%d/%d transport_errors=%d semantic_errors=%d errors=%v",
			epoch,
			summary.successes,
			threshold,
			summary.conflicts,
			threshold,
			summary.transportErrors,
			summary.semanticErrors,
			summary.errs,
		)
		return pki.ErrInvalidPostEpoch
	}

	c.rememberLastPostReplicaSummary(epoch, summary)
	return fmt.Errorf(
		"PostReplica(%d) failed: %d/%d successes, %d/%d conflicts, transport_errors=%d semantic_errors=%d, errors: %v",
		epoch,
		summary.successes,
		threshold,
		summary.conflicts,
		threshold,
		summary.transportErrors,
		summary.semanticErrors,
		summary.errs,
	)
}

// fetchResult carries the outcome of a single authority's consensus fetch
// when racing peers in parallel.
type fetchResult struct {
	peer   string
	doc    *pki.Document
	rawDoc []byte
	sigs   int
	err    error
}

// GetPKIDocumentForEpoch returns the PKI document for the provided epoch.
//
// The configured authorities are contacted in parallel. The first peer to
// return a valid, threshold-signed, well-formed document for the requested
// epoch wins and the remaining in-flight fetches are cancelled. A single
// unreachable or slow authority cannot delay progress when at least one peer
// is responsive.
func (c *Client) GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	// Generate a random keypair to use for the link authentication.
	_, linkKey, err := c.cfg.KEMScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// raceCtx is the cancellation root for the per-authority fetchers.
	// The deferred cancel fires on every return path (success on first
	// valid result, or fall-through after every peer was rejected) and
	// signals the remaining in-flight fetchers to abort.
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Three goroutine populations cooperate here:
	//
	//   1. N fetcher goroutines (one per authority) each write exactly
	//      one fetchResult into the buffered results channel and exit.
	//   2. One drain goroutine waits for all fetchers to exit and then
	//      closes the channel.
	//   3. The main goroutine (this function) reads from the channel.
	//
	// The channel is buffered to len(c.cfg.Authorities) so that every
	// fetcher can write its result without blocking even after we have
	// already returned from the main goroutine on an earlier peer's
	// success. The buffer guarantees that the late writers never wedge
	// against an unread channel; raceCtx cancellation hurries them
	// along, but the buffer is what lets them exit cleanly.
	results := make(chan fetchResult, len(c.cfg.Authorities))
	var fetchers worker.Worker // tracks the per-authority fetchers
	for _, auth := range c.cfg.Authorities {
		fetchers.Go(func() {
			results <- c.fetchAndValidate(raceCtx, auth, linkKey, epoch)
		})
	}
	go func() {
		fetchers.Wait()
		close(results)
	}()

	for res := range results {
		if res.err != nil {
			c.log.Errorf("Get: %s: %v", res.peer, res.err)
			continue
		}
		c.log.Noticef("Get: retrieved valid consensus from %s for epoch %d (%d sigs)", res.peer, epoch, res.sigs)
		// One peer's response is sufficient: fetchAndValidate has
		// already verified the document via cert.VerifyThreshold,
		// which proves that threshold-many dirauths signed the
		// consensus. We do not need responses from threshold-many
		// peers; any one peer's signed document carries the threshold
		// inside it.
		//
		// Returning here triggers the deferred cancel above, which
		// terminates the remaining in-flight fetchers. They write
		// their final result into the buffered channel and exit; the
		// drain goroutine sees the wait-group go to zero and closes
		// the channel.
		return res.doc, res.rawDoc, nil
	}

	e, _, _ := epochtime.Now()
	if epoch <= e {
		return nil, nil, pki.ErrDocumentGone
	}

	return nil, nil, pki.ErrNoDocument
}

// fetchAndValidate retrieves a consensus from a single authority and applies
// the full set of validation checks. The returned fetchResult carries either
// a validated document or the reason this peer was rejected.
func (c *Client) fetchAndValidate(ctx context.Context, auth *config.Authority, linkKey kem.PrivateKey, epoch uint64) fetchResult {
	res := fetchResult{peer: auth.Identifier}

	resp, err := c.pool.fetchConsensus(auth, ctx, linkKey, epoch)
	if err != nil {
		res.err = err
		return res
	}
	r, ok := resp.(*commands.Consensus)
	if !ok {
		res.err = fmt.Errorf("unexpected response type %T", resp)
		return res
	}
	if r.ErrorCode != commands.ConsensusOk {
		res.err = fmt.Errorf("consensus error code %d", r.ErrorCode)
		return res
	}
	_, good, _, err := cert.VerifyThreshold(c.verifiers, c.threshold, r.Payload)
	if err != nil {
		res.err = fmt.Errorf("signature verification failed: %v", err)
		return res
	}
	doc, err := pki.ParseDocument(r.Payload)
	if err != nil {
		res.err = fmt.Errorf("parse failed: %v", err)
		return res
	}
	if err = pki.IsDocumentWellFormed(doc, c.verifiers); err != nil {
		res.err = fmt.Errorf("malformed document: %v", err)
		return res
	}
	if doc.Epoch != epoch {
		res.err = fmt.Errorf("epoch mismatch: doc=%d want=%d", doc.Epoch, epoch)
		return res
	}
	res.doc = doc
	res.rawDoc = r.Payload
	res.sigs = len(good)
	return res
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
