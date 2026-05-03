// wire_handler.go - Katzenpost non-voting authority connection handler.
// Copyright (C) 2017, 2018  Yawning Angel, masala and David Stainton.
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

package server

import (
	"crypto/hmac"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/quic/common"
)

// isQUICConn returns true if the connection is a QUIC connection
func isQUICConn(conn net.Conn) bool {
	_, ok := conn.(*common.QuicConn)
	return ok
}

func (s *Server) onConn(conn net.Conn) {
	rAddr := conn.RemoteAddr()
	lAddr := conn.LocalAddr()

	phaseAtAccept, remainingAtAccept := s.state.PhaseInfo()
	acceptedAt := time.Now()

	s.log.Debugf(
		"Accepted new connection: local=%v remote=%v phase_at_accept=%s remaining_at_accept=%v",
		lAddr,
		rAddr,
		phaseAtAccept,
		remainingAtAccept,
	)

	// Initialize the wire protocol session.
	auth := &wireAuthenticator{s: s}
	keyHash := hash.Sum256From(s.identityPublicKey)

	kemscheme := schemes.ByName(s.cfg.Server.WireKEMScheme)
	if kemscheme == nil {
		panic("kem scheme not found in registry")
	}

	cfg := &wire.SessionConfig{
		KEMScheme:          kemscheme,
		PKISignatureScheme: signSchemes.ByName(s.cfg.Server.PKISignatureScheme),
		Geometry:           s.geo,
		Authenticator:      auth,
		AdditionalData:     keyHash[:],
		AuthenticationKey:  s.linkKey,
		RandomReader:       rand.Reader,
	}

	wireConn, err := wire.NewPKISession(cfg, false)
	if err != nil {
		phaseNow, remainingNow := s.state.PhaseInfo()
		s.log.Debugf(
			"Peer %v: Failed to initialize session local=%v remote=%v phase_at_accept=%s remaining_at_accept=%v phase_now=%s remaining_now=%v elapsed=%v: %v",
			rAddr,
			lAddr,
			rAddr,
			phaseAtAccept,
			remainingAtAccept,
			phaseNow,
			remainingNow,
			time.Since(acceptedAt),
			err,
		)
		return
	}

	// wireConn.Close calls conn.Close. In quic, sends are nonblocking and Close
	// tears down the connection before the response was sent. So this waits
	// 100ms after the response has been served before closing the connection.
	defer func() {
		// Only delay for QUIC connections if needed
		if isQUICConn(conn) {
			<-time.After(time.Millisecond * 100)
		}
		wireConn.Close()
	}()

	// Handshake.
	handshakeTimeout := time.Duration(s.cfg.Server.HandshakeTimeoutSec) * time.Second
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	handshakeStart := time.Now()

	s.log.Debugf(
		"Peer %v: Starting responder handshake local=%v remote=%v phase_at_accept=%s remaining_at_accept=%v timeout=%v",
		rAddr,
		conn.LocalAddr(),
		conn.RemoteAddr(),
		phaseAtAccept,
		remainingAtAccept,
		handshakeTimeout,
	)

	if err = wireConn.Initialize(conn); err != nil {
		// Try to identify the peer from the handshake error.
		peerID := rAddr.String()
		if he, ok := wire.GetHandshakeError(err); ok && he.PeerCredentials != nil {
			if name := s.state.PeerName(he.PeerCredentials.AdditionalData); name != "" {
				peerID = name
			}
		}

		phaseNow, remainingNow := s.state.PhaseInfo()
		elapsed := time.Since(handshakeStart)
		classification := classifyAuthorityHandshakeFailure(err)

		if wire.IsNoHandshakeBytesError(err) {
			s.log.Debugf(
				"Peer %s: TCP connection closed before Noise handshake bytes local=%v remote=%v after=%v timeout=%v phase_at_accept=%s remaining_at_accept=%v phase_now=%s remaining_now=%v classification=%s: %v",
				peerID,
				conn.LocalAddr(),
				conn.RemoteAddr(),
				elapsed,
				handshakeTimeout,
				phaseAtAccept,
				remainingAtAccept,
				phaseNow,
				remainingNow,
				classification,
				err,
			)
			return
		}

		s.log.Errorf(
			"Peer %s: Failed session handshake local=%v remote=%v after=%v timeout=%v phase_at_accept=%s remaining_at_accept=%v phase_now=%s remaining_now=%v classification=%s: %v",
			peerID,
			conn.LocalAddr(),
			conn.RemoteAddr(),
			elapsed,
			handshakeTimeout,
			phaseAtAccept,
			remainingAtAccept,
			phaseNow,
			remainingNow,
			classification,
			err,
		)

		// Log detailed debug info (contains IPs, keys) at debug level only.
		s.log.Debugf("Peer %s: handshake failure details:\n%s", peerID, wire.GetDebugError(err))
		return
	}

	handshakeDuration := time.Since(handshakeStart)

	// Determine peer identifier for logging (name if known, otherwise IP)
	peerID := auth.peerName
	if peerID == "" {
		peerID = rAddr.String()
	}

	phaseAfterHandshake, remainingAfterHandshake := s.state.PhaseInfo()
	s.log.Debugf(
		"Peer %s: Handshake completed local=%v remote=%v in=%v phase_at_accept=%s remaining_at_accept=%v phase_now=%s remaining_now=%v",
		peerID,
		conn.LocalAddr(),
		conn.RemoteAddr(),
		handshakeDuration,
		phaseAtAccept,
		remainingAtAccept,
		phaseAfterHandshake,
		remainingAfterHandshake,
	)

	// Receive a command.
	recvStart := time.Now()
	cmd, err := wireConn.RecvCommand()
	if err != nil {
		phaseNow, remainingNow := s.state.PhaseInfo()
		s.log.Debugf(
			"Peer %s: Failed to receive command local=%v remote=%v after_handshake=%v recv_elapsed=%v phase_at_accept=%s remaining_at_accept=%v phase_now=%s remaining_now=%v classification=%s: %v",
			peerID,
			conn.LocalAddr(),
			conn.RemoteAddr(),
			handshakeDuration,
			time.Since(recvStart),
			phaseAtAccept,
			remainingAtAccept,
			phaseNow,
			remainingNow,
			classifyAuthorityCommandIOFailure(err),
			err,
		)
		return
	}
	recvDuration := time.Since(recvStart)

	conn.SetDeadline(time.Time{})

	// Log timing for all commands
	phaseAfterRecv, remainingAfterRecv := s.state.PhaseInfo()
	s.log.Debugf(
		"Peer %s: Received %T in=%v handshake=%v total=%v local=%v remote=%v phase_now=%s remaining_now=%v",
		peerID,
		cmd,
		recvDuration,
		handshakeDuration,
		handshakeDuration+recvDuration,
		conn.LocalAddr(),
		conn.RemoteAddr(),
		phaseAfterRecv,
		remainingAfterRecv,
	)

	// Parse the command, and craft the response.
	handlerStart := time.Now()
	var resp commands.Command
	if auth.isClient {
		resp = s.onClient(peerID, cmd)
	} else if auth.isMix {
		resp = s.onMix(peerID, cmd, auth.peerIdentityKeyHash)
	} else if auth.isReplica {
		resp = s.onReplica(peerID, cmd, auth.peerIdentityKeyHash)
	} else if auth.isAuthority {
		resp = s.onAuthority(peerID, cmd)
	} else {
		panic("wtf") // should only happen if there is a bug in wireAuthenticator
	}

	handlerDuration := time.Since(handlerStart)
	phaseAfterHandler, remainingAfterHandler := s.state.PhaseInfo()
	s.log.Debugf(
		"Peer %s: Handler completed command=%T response=%T handler_elapsed=%v total_since_accept=%v phase_now=%s remaining_now=%v",
		peerID,
		cmd,
		resp,
		handlerDuration,
		time.Since(acceptedAt),
		phaseAfterHandler,
		remainingAfterHandler,
	)

	// Send the response, if any.
	if resp != nil {
		responseTimeout := time.Duration(s.cfg.Server.ResponseTimeoutSec) * time.Second
		conn.SetDeadline(time.Now().Add(responseTimeout))

		sendStart := time.Now()
		s.log.Debugf(
			"Peer %s: Sending response command=%T response=%T local=%v remote=%v timeout=%v phase_now=%s remaining_now=%v total_since_accept=%v",
			peerID,
			cmd,
			resp,
			conn.LocalAddr(),
			conn.RemoteAddr(),
			responseTimeout,
			phaseAfterHandler,
			remainingAfterHandler,
			time.Since(acceptedAt),
		)

		if err = wireConn.SendCommand(resp); err != nil {
			phaseNow, remainingNow := s.state.PhaseInfo()
			s.log.Warningf(
				"Peer %s: Failed to send response command=%T response=%T local=%v remote=%v after=%v timeout=%v phase_at_accept=%s remaining_at_accept=%v phase_now=%s remaining_now=%v classification=%s total_since_accept=%v: %v",
				peerID,
				cmd,
				resp,
				conn.LocalAddr(),
				conn.RemoteAddr(),
				time.Since(sendStart),
				responseTimeout,
				phaseAtAccept,
				remainingAtAccept,
				phaseNow,
				remainingNow,
				classifyAuthorityCommandIOFailure(err),
				time.Since(acceptedAt),
				err,
			)
			return
		}

		phaseAfterSend, remainingAfterSend := s.state.PhaseInfo()
		s.log.Debugf(
			"Peer %s: Sent response command=%T response=%T local=%v remote=%v send_elapsed=%v total_since_accept=%v phase_now=%s remaining_now=%v",
			peerID,
			cmd,
			resp,
			conn.LocalAddr(),
			conn.RemoteAddr(),
			time.Since(sendStart),
			time.Since(acceptedAt),
			phaseAfterSend,
			remainingAfterSend,
		)
	}
}

func classifyAuthorityHandshakeFailure(err error) string {
	if err == nil {
		return "none"
	}

	s := err.Error()

	switch {
	case strings.Contains(s, "failed to send NoOp during finalization") &&
		strings.Contains(s, "broken pipe"):
		return "peer_closed_during_responder_finalization_broken_pipe"
	case strings.Contains(s, "failed to send NoOp during finalization") &&
		strings.Contains(s, "connection reset by peer"):
		return "peer_closed_during_responder_finalization_reset"
	case strings.Contains(s, "failed to send NoOp during finalization") &&
		strings.Contains(s, "i/o timeout"):
		return "responder_finalization_send_timeout"
	case strings.Contains(s, "failed to send NoOp during finalization"):
		return "responder_finalization_send_failed"
	case strings.Contains(s, "failed to receive NoOp during finalization"):
		return "initiator_finalization_receive_failed"
	case strings.Contains(s, "failed to receive message 1"):
		return "responder_message_1_receive_failed"
	case strings.Contains(s, "failed to receive message 2"):
		return "initiator_message_2_receive_failed"
	case strings.Contains(s, "failed to receive message 3"):
		return "responder_message_3_receive_failed"
	case strings.Contains(s, "failed to receive message 4"):
		return "initiator_message_4_receive_failed"
	case strings.Contains(s, "peer authentication failed"):
		return "peer_authentication_failed"
	case strings.Contains(s, "protocol version mismatch"):
		return "protocol_version_mismatch"
	case strings.Contains(s, "unexpected EOF"):
		return "unexpected_eof"
	case strings.Contains(s, "EOF"):
		return "eof"
	case strings.Contains(s, "i/o timeout"):
		return "io_timeout"
	case strings.Contains(s, "connection reset by peer"):
		return "connection_reset_by_peer"
	case strings.Contains(s, "broken pipe"):
		return "broken_pipe"
	default:
		return "unclassified_handshake_failure"
	}
}

func classifyAuthorityCommandIOFailure(err error) string {
	if err == nil {
		return "none"
	}

	s := err.Error()

	switch {
	case strings.Contains(s, "broken pipe"):
		return "broken_pipe"
	case strings.Contains(s, "connection reset by peer"):
		return "connection_reset_by_peer"
	case strings.Contains(s, "unexpected EOF"):
		return "unexpected_eof"
	case strings.Contains(s, "EOF"):
		return "eof"
	case strings.Contains(s, "i/o timeout"):
		return "io_timeout"
	default:
		return "unclassified_command_io_failure"
	}
}

func (s *Server) onClient(peerID string, cmd commands.Command) commands.Command {
	s.log.Debug("onClient")
	var resp commands.Command
	switch c := cmd.(type) {
	case *commands.GetConsensus:
		resp = s.onGetConsensus(peerID, c)
	default:
		s.log.Debugf("Peer %s: Invalid request: %T", peerID, c)
		return nil
	}
	return resp
}

func (s *Server) onMix(peerID string, cmd commands.Command, peerIdentityKeyHash []byte) commands.Command {
	s.log.Debug("onMix")
	var resp commands.Command
	switch c := cmd.(type) {
	case *commands.GetConsensus:
		resp = s.onGetConsensus(peerID, c)
	case *commands.PostDescriptor:
		resp = s.onPostDescriptor(peerID, c, peerIdentityKeyHash)
	default:
		s.log.Debugf("Peer %s: Invalid request: %T", peerID, c)
		return nil
	}
	return resp
}

func (s *Server) onReplica(peerID string, cmd commands.Command, peerIdentityKeyHash []byte) commands.Command {
	s.log.Debug("onReplica")
	var resp commands.Command
	switch c := cmd.(type) {
	case *commands.PostReplicaDescriptor:
		resp = s.onPostReplicaDescriptor(peerID, c, peerIdentityKeyHash)
	default:
		s.log.Debugf("Peer %s: Invalid request: %T", peerID, c)
		return nil
	}
	return resp
}

func (s *Server) onAuthority(peerID string, cmd commands.Command) commands.Command {
	s.log.Debugf("onAuthority: Received command from authority peer %s: %T", peerID, cmd)
	var resp commands.Command
	switch c := cmd.(type) {
	case *commands.GetConsensus:
		s.log.Debugf("onAuthority: Processing GetConsensus request from authority %s for epoch %d", peerID, c.Epoch)
		resp = s.onGetConsensus(peerID, c)
	case *commands.Vote:
		s.log.Debugf("onAuthority: Processing Vote upload from authority %s for epoch %d", peerID, c.Epoch)
		resp = s.state.onVoteUpload(c)
	case *commands.Cert:
		s.log.Debugf("onAuthority: Processing Certificate upload from authority %s for epoch %d", peerID, c.Epoch)
		resp = s.state.onCertUpload(c)
	case *commands.Reveal:
		s.log.Debugf("onAuthority: Processing Reveal upload from authority %s for epoch %d", peerID, c.Epoch)
		resp = s.state.onRevealUpload(c)
	case *commands.Sig:
		s.log.Debugf("onAuthority: Processing Signature upload from authority %s for epoch %d", peerID, c.Epoch)
		resp = s.state.onSigUpload(c)
	default:
		s.log.Errorf("onAuthority: INVALID REQUEST from authority peer %s: unsupported command type %T", peerID, c)
		return nil
	}
	s.log.Debugf("onAuthority: Completed processing command %T from authority %s", cmd, peerID)
	return resp
}

func (s *Server) onGetConsensus(peerID string, cmd *commands.GetConsensus) commands.Command {
	s.log.Debugf("onGetConsensus: Processing consensus request from %s for epoch %d", peerID, cmd.Epoch)

	resp := &commands.Consensus{}
	doc, err := s.state.documentForEpoch(cmd.Epoch)
	if err != nil {
		switch err {
		case errGone:
			s.log.Debugf("onGetConsensus: Consensus document for epoch %d is gone (too old) for peer %s", cmd.Epoch, peerID)
			resp.ErrorCode = commands.ConsensusGone
		default:
			s.log.Debugf("onGetConsensus: Consensus document for epoch %d not found (not yet available) for peer %s: %v", cmd.Epoch, peerID, err)
			resp.ErrorCode = commands.ConsensusNotFound
		}
	} else {
		s.log.Debugf("onGetConsensus: Successfully retrieved consensus document for epoch %d for peer %s", cmd.Epoch, peerID)
		resp.ErrorCode = commands.ConsensusOk
		resp.Payload = doc
	}

	s.log.Debugf("onGetConsensus: Returning response to peer %s for epoch %d: error code %d", peerID, cmd.Epoch, resp.ErrorCode)
	return resp
}

func (s *Server) onPostReplicaDescriptor(peerID string, cmd *commands.PostReplicaDescriptor, pubKeyHash []byte) commands.Command {
	phase, timeRemaining := s.state.PhaseInfo()
	s.log.Debugf("onPostReplicaDescriptor: Received from peer %s for epoch %d (phase: %s, time remaining: %v)", peerID, cmd.Epoch, phase, timeRemaining)

	resp := &commands.PostReplicaDescriptorStatus{
		ErrorCode: commands.DescriptorInvalid,
	}

	// Ensure the epoch is somewhat sane.
	now, _, _ := epochtime.Now()
	switch cmd.Epoch {
	case now - 1, now, now + 1:
		// Nodes will always publish the descriptor for the current epoch on
		// launch, which may be off by one period, depending on how skewed
		// the node's clock is and the current time.
	default:
		// The peer is publishing for an epoch that's invalid.
		s.log.Errorf("Peer %s: Invalid descriptor epoch '%v'", peerID, cmd.Epoch)
		return resp
	}

	// Validate and deserialize the SignedReplicaUpload.
	signedUpload := new(pki.SignedReplicaUpload)
	err := signedUpload.Unmarshal(cmd.Payload)
	if err != nil {
		s.log.Errorf("Peer %s: Invalid descriptor: %v", peerID, err)
		return resp
	}

	desc := signedUpload.ReplicaDescriptor
	if desc == nil {
		s.log.Noticef(
			"Peer %s: Rejecting nil uploaded replica descriptor epoch %d",
			strconv.QuoteToASCII(peerID),
			cmd.Epoch,
		)
		return resp
	}

	// Ensure that the descriptor is signed by the peer that is posting.
	identityKeyHash := hash.Sum256(desc.IdentityKey)
	if !hmac.Equal(identityKeyHash[:], pubKeyHash) {
		s.log.Errorf("Peer %s: Identity key hash '%x' is not link key '%x'.", peerID, hash.Sum256(desc.IdentityKey), pubKeyHash)
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}

	pkiSignatureScheme := signSchemes.ByName(s.cfg.Server.PKISignatureScheme)
	descIdPubKey, err := pkiSignatureScheme.UnmarshalBinaryPublicKey(desc.IdentityKey)
	if err != nil {
		s.log.Error("failed to unmarshal descriptor IdentityKey")
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}

	if !signedUpload.Verify(descIdPubKey) {
		s.log.Error("PostDescriptorStatus contained a SignedUpload with an invalid signature")
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}

	// Ensure that the descriptor is from an allowed peer.
	if !s.state.isReplicaDescriptorAuthorized(desc) {
		s.log.Errorf("Peer %s: Identity key hash '%x' not authorized", peerID, hash.Sum256(desc.IdentityKey))
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}

	if err := pki.IsReplicaDescriptorWellFormed(desc, cmd.Epoch); err != nil {
		s.log.Noticef(
			"Peer %s: Rejecting malformed uploaded replica descriptor for node %s epoch %d: %s",
			strconv.QuoteToASCII(peerID),
			strconv.QuoteToASCII(desc.Name),
			cmd.Epoch,
			strconv.QuoteToASCII(err.Error()),
		)
		return resp
	}

	// Hand the replica descriptor off to the state worker. As long as this returns
	// a nil, the authority "accepts" the replica descriptor.
	err = s.state.onReplicaDescriptorUpload(cmd.Payload, desc, cmd.Epoch)
	if err != nil {
		// This is either a internal server error or the peer is trying to
		// retroactively modify their descriptor. This should disambituate
		// the condition, but the latter is more likely.
		s.log.Errorf("Peer %s: Rejected probably a conflict: %v", peerID, err)
		resp.ErrorCode = commands.DescriptorConflict
		return resp
	}

	// Return a successful response.
	s.log.Noticef(
		"Peer %s: Accepted uploaded replica descriptor for node %s epoch %d",
		strconv.QuoteToASCII(peerID),
		strconv.QuoteToASCII(desc.Name),
		cmd.Epoch,
	)
	resp.ErrorCode = commands.DescriptorOk
	return resp
}

func (s *Server) onPostDescriptor(peerID string, cmd *commands.PostDescriptor, pubKeyHash []byte) commands.Command {
	phase, timeRemaining := s.state.PhaseInfo()
	s.log.Debugf("onPostDescriptor: Received descriptor from peer %s for epoch %d (phase: %s, time remaining: %v)", peerID, cmd.Epoch, phase, timeRemaining)

	resp := &commands.PostDescriptorStatus{
		ErrorCode: commands.DescriptorInvalid,
	}

	// Ensure the epoch is somewhat sane.
	now, _, _ := epochtime.Now()
	s.log.Debugf("onPostDescriptor: Validating epoch from peer %s: descriptor epoch %d, current epoch %d", peerID, cmd.Epoch, now)
	switch cmd.Epoch {
	case now - 1, now, now + 1:
		// Nodes will always publish the descriptor for the current epoch on
		// launch, which may be off by one period, depending on how skewed
		// the node's clock is and the current time.
		s.log.Debugf("onPostDescriptor: Epoch validation passed from peer %s: epoch %d is within acceptable range", peerID, cmd.Epoch)
	default:
		// The peer is publishing for an epoch that's invalid.
		s.log.Errorf("onPostDescriptor: EPOCH VALIDATION FAILED from peer %s: invalid descriptor epoch %d (current: %d, acceptable: %d-%d)", peerID, cmd.Epoch, now, now-1, now+1)
		return resp
	}

	// Validate and deserialize the SignedUpload.
	s.log.Debugf("onPostDescriptor: Deserializing SignedUpload from peer %s", strconv.QuoteToASCII(peerID))
	signedUpload := new(pki.SignedUpload)
	err := signedUpload.Unmarshal(cmd.Payload)
	if err != nil {
		s.log.Errorf("onPostDescriptor: DESERIALIZATION FAILED from peer %s: invalid descriptor: %s", strconv.QuoteToASCII(peerID), strconv.QuoteToASCII(err.Error()))
		return resp
	}
	s.log.Debugf("onPostDescriptor: Successfully deserialized SignedUpload from peer %s", strconv.QuoteToASCII(peerID))

	desc := signedUpload.MixDescriptor
	if desc == nil {
		s.log.Noticef(
			"onPostDescriptor: Rejecting nil uploaded descriptor from peer %s epoch %d",
			strconv.QuoteToASCII(peerID),
			cmd.Epoch,
		)
		return resp
	}
	s.log.Debugf("onPostDescriptor: Processing descriptor from peer %s", strconv.QuoteToASCII(peerID))

	// Ensure that the descriptor is signed by the peer that is posting.
	s.log.Debugf("onPostDescriptor: Verifying identity key hash from peer %s", strconv.QuoteToASCII(peerID))
	identityKeyHash := hash.Sum256(desc.IdentityKey)
	if !hmac.Equal(identityKeyHash[:], pubKeyHash) {
		s.log.Errorf("onPostDescriptor: IDENTITY KEY MISMATCH from peer %s: identity key hash %x != link key %x", strconv.QuoteToASCII(peerID), hash.Sum256(desc.IdentityKey), pubKeyHash)
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}
	s.log.Debugf("onPostDescriptor: Identity key hash verification passed from peer %s", strconv.QuoteToASCII(peerID))

	pkiSignatureScheme := signSchemes.ByName(s.cfg.Server.PKISignatureScheme)
	s.log.Debugf("onPostDescriptor: Unmarshaling identity public key from peer %s", strconv.QuoteToASCII(peerID))
	descIdPubKey, err := pkiSignatureScheme.UnmarshalBinaryPublicKey(desc.IdentityKey)
	if err != nil {
		s.log.Errorf("onPostDescriptor: IDENTITY KEY UNMARSHAL FAILED from peer %s: %s", strconv.QuoteToASCII(peerID), strconv.QuoteToASCII(err.Error()))
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}
	s.log.Debugf("onPostDescriptor: Successfully unmarshaled identity public key from peer %s", strconv.QuoteToASCII(peerID))

	s.log.Debugf("onPostDescriptor: Verifying SignedUpload signature from peer %s", strconv.QuoteToASCII(peerID))
	if !signedUpload.Verify(descIdPubKey) {
		s.log.Errorf("onPostDescriptor: SIGNATURE VERIFICATION FAILED from peer %s: SignedUpload has invalid signature", strconv.QuoteToASCII(peerID))
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}
	s.log.Debugf("onPostDescriptor: SignedUpload signature verification passed for node %s from peer %s", strconv.QuoteToASCII(desc.Name), strconv.QuoteToASCII(peerID))

	// Ensure that the descriptor is from an allowed peer.
	s.log.Debugf("onPostDescriptor: Checking authorization for node %s from peer %s", strconv.QuoteToASCII(desc.Name), strconv.QuoteToASCII(peerID))
	if !s.state.isDescriptorAuthorized(desc) {
		s.log.Errorf("onPostDescriptor: AUTHORIZATION FAILED for node %s from peer %s: identity key hash %x not authorized", strconv.QuoteToASCII(desc.Name), strconv.QuoteToASCII(peerID), hash.Sum256(desc.IdentityKey))
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}
	s.log.Debugf("onPostDescriptor: Authorization check passed for node %s from peer %s", strconv.QuoteToASCII(desc.Name), strconv.QuoteToASCII(peerID))

	// TODO(david): Use the packet loss statistics to make decisions about how to
	// generate the consensus document.
	if err := pki.IsDescriptorWellFormed(desc, cmd.Epoch); err != nil {
		s.log.Noticef(
			"onPostDescriptor: Rejecting malformed uploaded descriptor for node %s epoch %d from peer %s: %s",
			strconv.QuoteToASCII(desc.Name),
			cmd.Epoch,
			strconv.QuoteToASCII(peerID),
			strconv.QuoteToASCII(err.Error()),
		)
		return resp
	}

	// Hand the descriptor off to the state worker. As long as this returns
	// a nil, the authority "accepts" the descriptor.
	s.log.Debugf("onPostDescriptor: Submitting descriptor for node %s epoch %d to state worker from peer %s", strconv.QuoteToASCII(desc.Name), cmd.Epoch, strconv.QuoteToASCII(peerID))
	err = s.state.onDescriptorUpload(cmd.Payload, desc, cmd.Epoch)
	if err != nil {
		// This is either a internal server error or the peer is trying to
		// retroactively modify their descriptor. This should disambituate
		// the condition, but the latter is more likely.
		s.log.Errorf("onPostDescriptor: DESCRIPTOR UPLOAD FAILED for node %s from peer %s: probably a conflict: %s", strconv.QuoteToASCII(desc.Name), strconv.QuoteToASCII(peerID), strconv.QuoteToASCII(err.Error()))
		resp.ErrorCode = commands.DescriptorConflict
		return resp
	}
	s.log.Debugf("onPostDescriptor: Successfully submitted descriptor for node %s to state worker from peer %s", strconv.QuoteToASCII(desc.Name), strconv.QuoteToASCII(peerID))

	// Return a successful response.
	s.log.Noticef(
		"onPostDescriptor: SUCCESS! Accepted uploaded descriptor for node %s epoch %d from peer %s",
		strconv.QuoteToASCII(desc.Name),
		cmd.Epoch,
		strconv.QuoteToASCII(peerID),
	)
	resp.ErrorCode = commands.DescriptorOk
	return resp
}

type wireAuthenticator struct {
	s *Server

	peerLinkKey         *ecdh.PublicKey
	peerIdentityKeyHash []byte
	peerName            string

	isClient    bool
	isMix       bool
	isReplica   bool
	isAuthority bool
}

// wireAuthenticatorSlowThreshold is the budget above which a single
// IsPeerValid call is considered suspicious.  The crypto and map
// lookups in this method should complete in well under a millisecond;
// anything slower is evidence of contention or scheduler starvation
// and is worth flagging.
const wireAuthenticatorSlowThreshold = 50 * time.Millisecond

func (a *wireAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	start := time.Now()
	defer func() {
		if elapsed := time.Since(start); elapsed > wireAuthenticatorSlowThreshold {
			peer := a.peerName
			if peer == "" {
				peer = "<unidentified>"
			}
			a.s.log.Warningf("wireAuthenticator: IsPeerValid slow: peer=%s elapsed=%v", peer, elapsed)
		}
	}()

	switch len(creds.AdditionalData) {
	case 0:
		a.isClient = true
		a.peerName = "client"
		return true
	case hash.HashSize:
	default:
		a.s.log.Warning("Rejecting authentication, invalid AD size.")
		return false
	}

	a.peerIdentityKeyHash = creds.AdditionalData
	a.peerName = a.s.state.PeerName(creds.AdditionalData)

	pk := [hash.HashSize]byte{}
	copy(pk[:], creds.AdditionalData[:hash.HashSize])

	_, isMix := a.s.state.authorizedMixes[pk]
	_, isGatewayNode := a.s.state.authorizedGatewayNodes[pk]
	_, isServiceNode := a.s.state.authorizedServiceNodes[pk]
	_, isReplicaNode := a.s.state.authorizedReplicaNodes[pk]
	_, isAuthority := a.s.state.authorizedAuthorities[pk]

	switch {
	case isMix || isGatewayNode || isServiceNode:
		a.isMix = true // Gateways and service nodes and mixes are all mixes.
		return true
	case isAuthority:
		linkKey, ok := a.s.state.authorityLinkKeys[pk]
		if !ok {
			a.s.log.Warning("Rejecting authority authentication, no link key entry.")
			return false
		}
		if creds.PublicKey == nil {
			a.s.log.Warning("Rejecting authority authentication, public key is nil.")
			return false
		}
		if !linkKey.Equal(creds.PublicKey) {
			a.s.log.Warning("Rejecting authority authentication, public key mismatch.")
			return false
		}
		a.isAuthority = true
		return true
	case isReplicaNode:
		a.isReplica = true
		return true
	default:
		a.s.log.Warning("Rejecting authority authentication, public key mismatch.")
		return false
	}

	// not reached
}
