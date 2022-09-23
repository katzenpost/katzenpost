// wire_handler.go - Katzenpost non-voting authority connection handler.
// Copyright (C) 2018  Yawning Angel.
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

	"github.com/katzenpost/katzenpost/authority/internal/s11n"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func (s *Server) onConn(conn net.Conn) {
	const (
		initialDeadline  = 30 * time.Second
		responseDeadline = 60 * time.Second
	)

	rAddr := conn.RemoteAddr()
	s.log.Debugf("Accepted new connection: %v", rAddr)

	defer func() {
		conn.Close()
		s.Done()
	}()

	// Initialize the wire protocol session.
	auth := &wireAuthenticator{s: s}
	keyHash := s.identityPublicKey.Sum256()
	cfg := &wire.SessionConfig{
		Geometry:          sphinx.DefaultGeometry(),
		Authenticator:     auth,
		AdditionalData:    keyHash[:],
		AuthenticationKey: s.linkKey,
		RandomReader:      rand.Reader,
	}
	wireConn, err := wire.NewSession(cfg, false)
	if err != nil {
		s.log.Debugf("Peer %v: Failed to initialize session: %v", rAddr, err)
		return
	}
	defer wireConn.Close()

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
	switch c := cmd.(type) {
	case *commands.GetConsensus:
		resp = s.onGetConsensus(rAddr, c)
	case *commands.PostDescriptor:
		if auth.peerIdentityKeyHash == nil {
			// A client trying to post is actively evil, don't even dignify
			// it with a response.
			s.log.Errorf("Peer %v: Not allowed to post.", rAddr)
			return
		}
		resp = s.onPostDescriptor(rAddr, c, auth.peerIdentityKeyHash)
	default:
		s.log.Debugf("Peer %v: Invalid request: %T", rAddr, c)
		return
	}

	// Send the response, if any.
	if resp != nil {
		conn.SetDeadline(time.Now().Add(responseDeadline))
		if err = wireConn.SendCommand(resp); err != nil {
			s.log.Debugf("Peer %v: Failed to send response: %v", rAddr, err)
		}
	}
}

func (s *Server) onGetConsensus(rAddr net.Addr, cmd *commands.GetConsensus) commands.Command {
	resp := &commands.Consensus{}
	doc, err := s.state.documentForEpoch(cmd.Epoch)
	if err != nil {
		s.log.Errorf("Peer %v: Failed to retrieve document for epoch '%v': %v", rAddr, cmd.Epoch, err)
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
		s.log.Errorf("Peer %v: Invalid descriptor epoch '%v',"+
			" epoch should be around '%v'", rAddr, cmd.Epoch, now)
		return resp
	}

	// Validate and deserialize the descriptor.
	verifier, err := s11n.GetVerifierFromDescriptor(cmd.Payload)
	if err != nil {
		s.log.Errorf("Peer %v: Invalid descriptor: %v", rAddr, err)
		return resp
	}
	desc, err := s11n.VerifyAndParseDescriptor(verifier, cmd.Payload, cmd.Epoch)
	if err != nil {
		s.log.Errorf("Peer %v: Invalid descriptor: %v", rAddr, err)
		return resp
	}

	// Ensure that the descriptor is signed by the peer that is posting.
	idPubKeyHash := desc.IdentityKey.Sum256()
	if !hmac.Equal(idPubKeyHash[:], pubKeyHash) {
		s.log.Errorf("Peer %v: Identity key hash '%x' is not id key hash '%x'.", rAddr, idPubKeyHash[:], pubKeyHash)
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}

	// Ensure that the descriptor is from an allowed peer.
	if !s.state.isDescriptorAuthorized(desc) {
		identityKeyHash := desc.IdentityKey.Sum256()
		s.log.Errorf("Peer %v: Identity key hash '%x' not authorized", rAddr, identityKeyHash[:])
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}

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
	peerIdentityKeyHash []byte
}

func (a *wireAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	// Just allow clients to connect with fetch access.
	switch len(creds.AdditionalData) {
	case 0:
		return true
	case sign.PublicKeyHashSize:
	default:
		a.s.log.Debugf("Rejecting authentication, invalid AD size.")
		return false
	}

	a.peerIdentityKeyHash = creds.AdditionalData

	pk := [sign.PublicKeyHashSize]byte{}
	copy(pk[:], creds.AdditionalData[:sign.PublicKeyHashSize])

	if !(a.s.state.authorizedMixes[pk] || a.s.state.authorizedProviders[pk] != "") {
		a.s.log.Debugf("Rejecting authentication, not a valid mix/provider.")
		return false
	}

	return true
}
