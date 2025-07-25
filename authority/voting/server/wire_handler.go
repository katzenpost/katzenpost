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
	const (
		initialDeadline  = 30 * time.Second
		responseDeadline = 60 * time.Second
	)

	rAddr := conn.RemoteAddr()
	s.log.Debugf("Accepted new connection: %v", rAddr)

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
		s.log.Debugf("Peer %v: Failed to initialize session: %v", rAddr, err)
		return
	}

	// wireConn.Close calls conn.Close. In quic, sends are nonblocking and Close
	// tears down the connection before the response was sent.
	// So this waits 100ms after the response has been served before closing the connection.
	defer func() {
		// Only delay for QUIC connections if needed
		if isQUICConn(conn) {
			<-time.After(time.Millisecond * 100)
		}
		wireConn.Close()
	}()

	// Handshake.
	conn.SetDeadline(time.Now().Add(initialDeadline))
	if err = wireConn.Initialize(conn); err != nil {
		s.log.Debugf("Peer %v: Failed session handshake: %v", rAddr, err)
		return
	}

	// Receive a command.
	cmd, err := wireConn.RecvCommand()
	if err != nil {
		s.log.Debugf("Peer %v: Failed to receive command: %v", rAddr, err)
		return
	}
	conn.SetDeadline(time.Time{})

	// Parse the command, and craft the response.
	var resp commands.Command
	if auth.isClient {
		resp = s.onClient(rAddr, cmd)
	} else if auth.isMix {
		resp = s.onMix(rAddr, cmd, auth.peerIdentityKeyHash)
	} else if auth.isReplica {
		resp = s.onReplica(rAddr, cmd, auth.peerIdentityKeyHash)
	} else if auth.isAuthority {
		resp = s.onAuthority(rAddr, cmd)
	} else {
		panic("wtf") // should only happen if there is a bug in wireAuthenticator
	}

	// Send the response, if any.
	if resp != nil {
		conn.SetDeadline(time.Now().Add(responseDeadline))
		if err = wireConn.SendCommand(resp); err != nil {
			s.log.Debugf("Peer %v: Failed to send response: %v", rAddr, err)
		}
	}
}

func (s *Server) onClient(rAddr net.Addr, cmd commands.Command) commands.Command {
	s.log.Debug("onClient")
	var resp commands.Command
	switch c := cmd.(type) {
	case *commands.GetConsensus:
		resp = s.onGetConsensus(rAddr, c)
	default:
		s.log.Debugf("Peer %v: Invalid request: %T", rAddr, c)
		return nil
	}
	return resp
}

func (s *Server) onMix(rAddr net.Addr, cmd commands.Command, peerIdentityKeyHash []byte) commands.Command {
	s.log.Debug("onMix")
	var resp commands.Command
	switch c := cmd.(type) {
	case *commands.GetConsensus:
		resp = s.onGetConsensus(rAddr, c)
	case *commands.PostDescriptor:
		resp = s.onPostDescriptor(rAddr, c, peerIdentityKeyHash)
	default:
		s.log.Debugf("Peer %v: Invalid request: %T", rAddr, c)
		return nil
	}
	return resp
}

func (s *Server) onReplica(rAddr net.Addr, cmd commands.Command, peerIdentityKeyHash []byte) commands.Command {
	s.log.Debug("onReplica")
	var resp commands.Command
	switch c := cmd.(type) {
	case *commands.PostReplicaDescriptor:
		resp = s.onPostReplicaDescriptor(rAddr, c, peerIdentityKeyHash)
	default:
		s.log.Debugf("Peer %v: Invalid request: %T", rAddr, c)
		return nil
	}
	return resp
}

func (s *Server) onAuthority(rAddr net.Addr, cmd commands.Command) commands.Command {
	s.log.Debugf("onAuthority: Received command from authority peer %v: %T", rAddr, cmd)
	var resp commands.Command
	switch c := cmd.(type) {
	case *commands.GetConsensus:
		s.log.Debugf("onAuthority: Processing GetConsensus request from authority %v for epoch %d", rAddr, c.Epoch)
		resp = s.onGetConsensus(rAddr, c)
	case *commands.Vote:
		s.log.Debugf("onAuthority: Processing Vote upload from authority %v for epoch %d", rAddr, c.Epoch)
		resp = s.state.onVoteUpload(c)
	case *commands.Cert:
		s.log.Debugf("onAuthority: Processing Certificate upload from authority %v for epoch %d", rAddr, c.Epoch)
		resp = s.state.onCertUpload(c)
	case *commands.Reveal:
		s.log.Debugf("onAuthority: Processing Reveal upload from authority %v for epoch %d", rAddr, c.Epoch)
		resp = s.state.onRevealUpload(c)
	case *commands.Sig:
		s.log.Debugf("onAuthority: Processing Signature upload from authority %v for epoch %d", rAddr, c.Epoch)
		resp = s.state.onSigUpload(c)
	default:
		s.log.Errorf("onAuthority: INVALID REQUEST from authority peer %v: unsupported command type %T", rAddr, c)
		return nil
	}
	s.log.Debugf("onAuthority: Completed processing command %T from authority %v", cmd, rAddr)
	return resp
}

func (s *Server) onGetConsensus(rAddr net.Addr, cmd *commands.GetConsensus) commands.Command {
	s.log.Debugf("onGetConsensus: Processing consensus request from %v for epoch %d", rAddr, cmd.Epoch)
	resp := &commands.Consensus{}
	doc, err := s.state.documentForEpoch(cmd.Epoch)
	if err != nil {
		switch err {
		case errGone:
			s.log.Debugf("onGetConsensus: Consensus document for epoch %d is gone (too old) for peer %v", cmd.Epoch, rAddr)
			resp.ErrorCode = commands.ConsensusGone
		default:
			s.log.Debugf("onGetConsensus: Consensus document for epoch %d not found (not yet available) for peer %v: %v", cmd.Epoch, rAddr, err)
			resp.ErrorCode = commands.ConsensusNotFound
		}
	} else {
		s.log.Debugf("onGetConsensus: Successfully retrieved consensus document for epoch %d for peer %v", cmd.Epoch, rAddr)
		resp.ErrorCode = commands.ConsensusOk
		resp.Payload = doc
	}
	s.log.Debugf("onGetConsensus: Returning response to peer %v for epoch %d: error code %d", rAddr, cmd.Epoch, resp.ErrorCode)
	return resp
}

func (s *Server) onPostReplicaDescriptor(rAddr net.Addr, cmd *commands.PostReplicaDescriptor, pubKeyHash []byte) commands.Command {
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
		s.log.Errorf("Peer %v: Invalid descriptor epoch '%v'", rAddr, cmd.Epoch)
		return resp
	}

	// Validate and deserialize the SignedReplicaUpload.
	signedUpload := new(pki.SignedReplicaUpload)
	err := signedUpload.Unmarshal(cmd.Payload)
	if err != nil {
		s.log.Errorf("Peer %v: Invalid descriptor: %v", rAddr, err)
		return resp
	}

	desc := signedUpload.ReplicaDescriptor

	// Ensure that the descriptor is signed by the peer that is posting.
	identityKeyHash := hash.Sum256(desc.IdentityKey)
	if !hmac.Equal(identityKeyHash[:], pubKeyHash) {
		s.log.Errorf("Peer %v: Identity key hash '%x' is not link key '%v'.", rAddr, hash.Sum256(desc.IdentityKey), pubKeyHash)
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
		s.log.Errorf("Peer %v: Identity key hash '%x' not authorized", rAddr, hash.Sum256(desc.IdentityKey))
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}

	// Hand the replica descriptor off to the state worker.  As long as this returns
	// a nil, the authority "accepts" the replica descriptor.
	err = s.state.onReplicaDescriptorUpload(cmd.Payload, desc, cmd.Epoch)
	if err != nil {
		// This is either a internal server error or the peer is trying to
		// retroactively modify their descriptor.  This should disambituate
		// the condition, but the latter is more likely.
		s.log.Errorf("Peer %v: Rejected probably a conflict: %v", rAddr, err)
		resp.ErrorCode = commands.DescriptorConflict
		return resp
	}

	// Return a successful response.
	s.log.Debugf("Peer %v: Accepted replica descriptor for epoch %v", rAddr, cmd.Epoch)
	resp.ErrorCode = commands.DescriptorOk
	return resp
}

func (s *Server) onPostDescriptor(rAddr net.Addr, cmd *commands.PostDescriptor, pubKeyHash []byte) commands.Command {
	s.log.Debugf("onPostDescriptor: Received descriptor from peer %v for epoch %d", rAddr, cmd.Epoch)
	resp := &commands.PostDescriptorStatus{
		ErrorCode: commands.DescriptorInvalid,
	}

	// Ensure the epoch is somewhat sane.
	now, _, _ := epochtime.Now()
	s.log.Debugf("onPostDescriptor: Validating epoch from peer %v: descriptor epoch %d, current epoch %d", rAddr, cmd.Epoch, now)
	switch cmd.Epoch {
	case now - 1, now, now + 1:
		// Nodes will always publish the descriptor for the current epoch on
		// launch, which may be off by one period, depending on how skewed
		// the node's clock is and the current time.
		s.log.Debugf("onPostDescriptor: Epoch validation passed from peer %v: epoch %d is within acceptable range", rAddr, cmd.Epoch)
	default:
		// The peer is publishing for an epoch that's invalid.
		s.log.Errorf("onPostDescriptor: EPOCH VALIDATION FAILED from peer %v: invalid descriptor epoch %d (current: %d, acceptable: %d-%d)", rAddr, cmd.Epoch, now, now-1, now+1)
		return resp
	}

	// Validate and deserialize the SignedUpload.
	s.log.Debugf("onPostDescriptor: Deserializing SignedUpload from peer %v", rAddr)
	signedUpload := new(pki.SignedUpload)
	err := signedUpload.Unmarshal(cmd.Payload)
	if err != nil {
		s.log.Errorf("onPostDescriptor: DESERIALIZATION FAILED from peer %v: invalid descriptor: %v", rAddr, err)
		return resp
	}
	s.log.Debugf("onPostDescriptor: Successfully deserialized SignedUpload from peer %v", rAddr)

	desc := signedUpload.MixDescriptor
	s.log.Debugf("onPostDescriptor: Processing descriptor for node %s from peer %v", desc.Name, rAddr)

	// Ensure that the descriptor is signed by the peer that is posting.
	s.log.Debugf("onPostDescriptor: Verifying identity key hash for node %s from peer %v", desc.Name, rAddr)
	identityKeyHash := hash.Sum256(desc.IdentityKey)
	if !hmac.Equal(identityKeyHash[:], pubKeyHash) {
		s.log.Errorf("onPostDescriptor: IDENTITY KEY MISMATCH for node %s from peer %v: identity key hash %x != link key %x", desc.Name, rAddr, hash.Sum256(desc.IdentityKey), pubKeyHash)
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}
	s.log.Debugf("onPostDescriptor: Identity key hash verification passed for node %s from peer %v", desc.Name, rAddr)

	pkiSignatureScheme := signSchemes.ByName(s.cfg.Server.PKISignatureScheme)

	s.log.Debugf("onPostDescriptor: Unmarshaling identity public key for node %s from peer %v", desc.Name, rAddr)
	descIdPubKey, err := pkiSignatureScheme.UnmarshalBinaryPublicKey(desc.IdentityKey)
	if err != nil {
		s.log.Errorf("onPostDescriptor: IDENTITY KEY UNMARSHAL FAILED for node %s from peer %v: %v", desc.Name, rAddr, err)
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}
	s.log.Debugf("onPostDescriptor: Successfully unmarshaled identity public key for node %s from peer %v", desc.Name, rAddr)

	s.log.Debugf("onPostDescriptor: Verifying SignedUpload signature for node %s from peer %v", desc.Name, rAddr)
	if !signedUpload.Verify(descIdPubKey) {
		s.log.Errorf("onPostDescriptor: SIGNATURE VERIFICATION FAILED for node %s from peer %v: SignedUpload has invalid signature", desc.Name, rAddr)
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}
	s.log.Debugf("onPostDescriptor: SignedUpload signature verification passed for node %s from peer %v", desc.Name, rAddr)

	// Ensure that the descriptor is from an allowed peer.
	s.log.Debugf("onPostDescriptor: Checking authorization for node %s from peer %v", desc.Name, rAddr)
	if !s.state.isDescriptorAuthorized(desc) {
		s.log.Errorf("onPostDescriptor: AUTHORIZATION FAILED for node %s from peer %v: identity key hash %x not authorized", desc.Name, rAddr, hash.Sum256(desc.IdentityKey))
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}
	s.log.Debugf("onPostDescriptor: Authorization check passed for node %s from peer %v", desc.Name, rAddr)

	// TODO(david): Use the packet loss statistics to make decisions about how to generate the consensus document.

	// Hand the descriptor off to the state worker.  As long as this returns
	// a nil, the authority "accepts" the descriptor.
	s.log.Debugf("onPostDescriptor: Submitting descriptor for node %s (epoch %d) to state worker from peer %v", desc.Name, cmd.Epoch, rAddr)
	err = s.state.onDescriptorUpload(cmd.Payload, desc, cmd.Epoch)
	if err != nil {
		// This is either a internal server error or the peer is trying to
		// retroactively modify their descriptor.  This should disambituate
		// the condition, but the latter is more likely.
		s.log.Errorf("onPostDescriptor: DESCRIPTOR UPLOAD FAILED for node %s from peer %v: probably a conflict: %v", desc.Name, rAddr, err)
		resp.ErrorCode = commands.DescriptorConflict
		return resp
	}
	s.log.Debugf("onPostDescriptor: Successfully submitted descriptor for node %s to state worker from peer %v", desc.Name, rAddr)

	// Return a successful response.
	s.log.Noticef("onPostDescriptor: SUCCESS! Accepted descriptor for node %s (epoch %d) from peer %v", desc.Name, cmd.Epoch, rAddr)
	resp.ErrorCode = commands.DescriptorOk
	return resp
}

type wireAuthenticator struct {
	s                   *Server
	peerLinkKey         *ecdh.PublicKey
	peerIdentityKeyHash []byte
	isClient            bool
	isMix               bool
	isReplica           bool
	isAuthority         bool
}

func (a *wireAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	switch len(creds.AdditionalData) {
	case 0:
		a.isClient = true
		return true
	case hash.HashSize:
	default:
		a.s.log.Warning("Rejecting authentication, invalid AD size.")
		return false
	}

	a.peerIdentityKeyHash = creds.AdditionalData

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
