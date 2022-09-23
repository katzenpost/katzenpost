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

	"github.com/katzenpost/katzenpost/authority/internal/s11n"
	"github.com/katzenpost/katzenpost/core/crypto/ecdh"
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
	if auth.isClient {
		resp = s.onClient(rAddr, cmd)
	} else if auth.isMix {
		resp = s.onMix(rAddr, cmd, auth.peerIdentityKeyHash)
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

func (s *Server) onAuthority(rAddr net.Addr, cmd commands.Command) commands.Command {
	s.log.Debug("onAuthority")
	var resp commands.Command
	switch c := cmd.(type) {
	case *commands.GetConsensus:
		resp = s.onGetConsensus(rAddr, c)
	case *commands.Vote:
		resp = s.onVote(c)
	case *commands.VoteStatus:
		s.log.Error("VoteStatus command is not allowed on Authority wire service listener.")
		return nil
	case *commands.Reveal:
		resp = s.onReveal(c)
	case *commands.RevealStatus:
		s.log.Error("RevealStatus command is not allowed on Authority wire service listener.")
		return nil
	default:
		s.log.Debugf("Peer %v: Invalid request: %T", rAddr, c)
		return nil
	}
	return resp
}

func (s *Server) onVote(cmd *commands.Vote) commands.Command {
	return s.state.onVoteUpload(cmd)
}

func (s *Server) onReveal(cmd *commands.Reveal) commands.Command {
	return s.state.onRevealUpload(cmd)
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
		s.log.Errorf("Peer %v: Invalid descriptor epoch '%v'", rAddr, cmd.Epoch)
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
	identityKeyHash := desc.IdentityKey.Sum256()
	if !hmac.Equal(identityKeyHash[:], pubKeyHash) {
		s.log.Errorf("Peer %v: Identity key hash '%x' is not link key '%v'.", rAddr, desc.IdentityKey, pubKeyHash)
		resp.ErrorCode = commands.DescriptorForbidden
		return resp
	}

	// Ensure that the descriptor is from an allowed peer.
	if !s.state.isDescriptorAuthorized(desc) {
		s.log.Errorf("Peer %v: Identity key '%v' not authorized", rAddr, desc.IdentityKey)
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
	peerLinkKey         *ecdh.PublicKey
	peerIdentityKeyHash []byte
	isClient            bool
	isMix               bool
	isAuthority         bool
}

func (a *wireAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	switch len(creds.AdditionalData) {
	case 0:
		a.isClient = true
		return true
	case sign.PublicKeyHashSize:
	default:
		a.s.log.Warning("Rejecting authentication, invalid AD size.")
		return false
	}

	a.peerIdentityKeyHash = creds.AdditionalData

	pk := [sign.PublicKeyHashSize]byte{}
	copy(pk[:], creds.AdditionalData[:sign.PublicKeyHashSize])

	_, isMix := a.s.state.authorizedMixes[pk]
	_, isProvider := a.s.state.authorizedProviders[pk]
	_, isAuthority := a.s.state.authorizedAuthorities[pk]

	if isMix || isProvider {
		a.isMix = true // Providers and mixes are both mixes. :)
		return true
	} else if isAuthority {
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
	} else {
		a.s.log.Warning("Rejecting authority authentication, public key mismatch.")
		return false
	}

	return false // Not reached.
}
