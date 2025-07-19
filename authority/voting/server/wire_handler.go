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
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func (s *Server) onConn(conn net.Conn) {
	const (
		initialDeadline  = 90 * time.Second // Increased from 30s to 90s for authority handshakes
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
	// So this waits 1000ms after the response has been served before closing the connection.
	// Increased from 100ms to 1000ms to allow sufficient time for NoOp command exchange
	// on slower network paths between authority nodes.
	defer func() {
		<-time.After(time.Millisecond * 1000)
		wireConn.Close()
	}()

	// Handshake.
	handshakeStart := time.Now()
	conn.SetDeadline(time.Now().Add(initialDeadline))
	if err = wireConn.Initialize(conn); err != nil {
		s.log.Debugf("Peer %v: Failed session handshake after %v: %v", rAddr, time.Since(handshakeStart), err)
		return
	}
	handshakeDuration := time.Since(handshakeStart)
	s.log.Debugf("Peer %v: Handshake completed successfully in %v", rAddr, handshakeDuration)

	// Get timing information from the wire session
	timing := wireConn.Timing()

	// Receive a command.
	cmd, err := wireConn.RecvCommand()
	if err != nil {
		s.log.Debugf("Peer %v: Failed to receive command: %v", rAddr, err)
		// Record failed connection for survey tracking
		s.recordConnectionTiming(auth, rAddr, false, err, &timing)
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

	// Record successful connection for survey tracking
	s.recordConnectionTiming(auth, rAddr, true, nil, &timing)

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
	var resp commands.Command
	switch c := cmd.(type) {
	case *commands.GetConsensus:
		resp = s.onGetConsensus(rAddr, c)
	case *commands.Vote:
		resp = s.state.onVoteUpload(c)
	case *commands.Cert:
		resp = s.state.onCertUpload(c)
	case *commands.Reveal:
		resp = s.state.onRevealUpload(c)
	case *commands.Sig:
		resp = s.state.onSigUpload(c)
	default:
		s.log.Debugf("Peer %v: Invalid request: %T", rAddr, c)
		return nil
	}
	return resp
}

func (s *Server) onGetConsensus(rAddr net.Addr, cmd *commands.GetConsensus) commands.Command {
	resp := &commands.Consensus{}
	doc, err := s.state.documentForEpoch(cmd.Epoch)
	if err != nil {
		switch err {
		case errGone:
			resp.ErrorCode = commands.ConsensusGone
		default:
			resp.ErrorCode = commands.ConsensusNotFound
		}
	} else {
		s.log.Debugf("Peer: %v: Serving document for epoch %v.", rAddr, cmd.Epoch)
		resp.ErrorCode = commands.ConsensusOk
		resp.Payload = doc
	}
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
	resp := &commands.PostDescriptorStatus{
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

	// Validate and deserialize the SignedUpload.
	signedUpload := new(pki.SignedUpload)
	err := signedUpload.Unmarshal(cmd.Payload)
	if err != nil {
		s.log.Errorf("Peer %v: Invalid descriptor: %v", rAddr, err)
		return resp
	}

	desc := signedUpload.MixDescriptor

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
	if !s.state.isDescriptorAuthorized(desc) {
		s.log.Errorf("Peer %v: Identity key hash '%x' not authorized", rAddr, hash.Sum256(desc.IdentityKey))
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}

	// TODO(david): Use the packet loss statistics to make decisions about how to generate the consensus document.

	// Hand the descriptor off to the state worker.  As long as this returns
	// a nil, the authority "accepts" the descriptor.
	err = s.state.onDescriptorUpload(cmd.Payload, desc, cmd.Epoch)
	if err != nil {
		// This is either a internal server error or the peer is trying to
		// retroactively modify their descriptor.  This should disambituate
		// the condition, but the latter is more likely.
		s.log.Errorf("Peer %v: Rejected probably a conflict: %v", rAddr, err)
		resp.ErrorCode = commands.DescriptorConflict
		return resp
	}

	// Return a successful response.
	s.log.Debugf("Peer %v: Accepted descriptor for epoch %v: '%v'", rAddr, cmd.Epoch, desc)
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
		a.s.log.Warningf("dirauth/wireAuth: IsPeerValid(): Remote Peer Credentials: ad_size=%d (expected: 0 or %d), link_key=%s",
			len(creds.AdditionalData), hash.HashSize, kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(creds.PublicKey)))
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
			// Try to get peer name from current PKI document
			peerName := "unknown"
			epoch, _, _ := epochtime.Now()
			a.s.state.RLock()
			if doc, exists := a.s.state.documents[epoch]; exists {
				if node, err := doc.GetNodeByKeyHash(&pk); err == nil {
					peerName = node.Name
				}
			}
			a.s.state.RUnlock()

			a.s.log.Warningf("Rejecting authority authentication, no link key entry for '%s'.", peerName)
			a.s.log.Warningf("dirauth/wireAuth: IsPeerValid(): Remote Peer Credentials: name=%s, identity_hash=%x, link_key=%s",
				peerName, creds.AdditionalData[:hash.HashSize], kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(creds.PublicKey)))
			// Log expected authorities for debugging
			a.s.log.Warningf("dirauth/wireAuth: IsPeerValid(): Expected authority link keys:")
			for authHash, authLinkKey := range a.s.state.authorityLinkKeys {
				authName := "unknown"
				a.s.state.RLock()
				if doc, exists := a.s.state.documents[epoch]; exists {
					if node, err := doc.GetNodeByKeyHash(&authHash); err == nil {
						authName = node.Name
					}
				}
				a.s.state.RUnlock()
				a.s.log.Warningf("dirauth/wireAuth: IsPeerValid():   - name=%s, identity_hash=%x, link_key=%s",
					authName, authHash[:], kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(authLinkKey)))
			}
			return false
		}
		if creds.PublicKey == nil {
			// Try to get peer name from current PKI document
			peerName := "unknown"
			epoch, _, _ := epochtime.Now()
			a.s.state.RLock()
			if doc, exists := a.s.state.documents[epoch]; exists {
				if node, err := doc.GetNodeByKeyHash(&pk); err == nil {
					peerName = node.Name
				}
			}
			a.s.state.RUnlock()

			a.s.log.Warningf("Rejecting authority authentication, public key is nil for '%s'.", peerName)
			a.s.log.Warningf("dirauth/wireAuth: IsPeerValid(): Remote Peer Credentials: name=%s, identity_hash=%x, link_key=nil",
				peerName, creds.AdditionalData[:hash.HashSize])
			return false
		}
		if !linkKey.Equal(creds.PublicKey) {
			// Try to get peer name from current PKI document
			peerName := "unknown"
			epoch, _, _ := epochtime.Now()
			a.s.state.RLock()
			if doc, exists := a.s.state.documents[epoch]; exists {
				if node, err := doc.GetNodeByKeyHash(&pk); err == nil {
					peerName = node.Name
				}
			}
			a.s.state.RUnlock()

			a.s.log.Warningf("Rejecting authority authentication, public key mismatch for '%s'.", peerName)
			a.s.log.Warningf("dirauth/wireAuth: IsPeerValid(): Expected link key for '%s': %s",
				peerName, kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(linkKey)))
			a.s.log.Warningf("dirauth/wireAuth: IsPeerValid(): Received link key for '%s': %s",
				peerName, kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(creds.PublicKey)))
			a.s.log.Warningf("dirauth/wireAuth: IsPeerValid(): Remote Peer Credentials: name=%s, identity_hash=%x",
				peerName, creds.AdditionalData[:hash.HashSize])
			return false
		}
		// Log successful authority authentication
		peerName := "unknown"
		epoch, _, _ := epochtime.Now()
		a.s.state.RLock()
		if doc, exists := a.s.state.documents[epoch]; exists {
			if node, err := doc.GetNodeByKeyHash(&pk); err == nil {
				peerName = node.Name
			}
		}
		a.s.state.RUnlock()
		a.s.log.Debugf("Authority authentication successful for '%s' (identity_hash=%x)", peerName, pk[:])
		a.isAuthority = true
		return true
	case isReplicaNode:
		a.isReplica = true
		return true
	default:
		// Try to get peer name from current PKI document
		peerName := "unknown"
		epoch, _, _ := epochtime.Now()
		a.s.state.RLock()
		if doc, exists := a.s.state.documents[epoch]; exists {
			if node, err := doc.GetNodeByKeyHash(&pk); err == nil {
				peerName = node.Name
			}
		}
		a.s.state.RUnlock()

		a.s.log.Warningf("Rejecting authentication, peer '%s' not found in any authorized category.", peerName)
		a.s.log.Warningf("dirauth/wireAuth: IsPeerValid(): Remote Peer Credentials: name=%s, identity_hash=%x, link_key=%s",
			peerName, creds.AdditionalData[:hash.HashSize], kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(creds.PublicKey)))
		a.s.log.Warningf("dirauth/wireAuth: IsPeerValid(): Peer '%s' not found in: mixes=%t, gateways=%t, services=%t, authorities=%t, replicas=%t",
			peerName, isMix, isGatewayNode, isServiceNode, isAuthority, isReplicaNode)
		return false
	}
	// not reached
}

// recordConnectionTiming records connection timing information for survey tracking
func (s *Server) recordConnectionTiming(auth *wireAuthenticator, rAddr net.Addr, success bool, err error, timing *wire.SessionTiming) {
	if auth.isAuthority {
		// Record authority peer connection
		if len(auth.peerIdentityKeyHash) == hash.HashSize {
			var peerID [hash.HashSize]byte
			copy(peerID[:], auth.peerIdentityKeyHash)
			s.state.recordIncomingConnection(peerID, success, err)
		}
	}
	// Note: We only track authority connections for minimal survey implementation
}
