// SPDX-FileCopyrightText: Copyright (C) 2017, 2018  Yawning Angel, masala and David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only

package main

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
	keyHash := hash.Sum256From(s.replicaPublicKey)

	kemscheme := schemes.ByName(s.cfg.WireKEMScheme)
	if kemscheme == nil {
		panic("kem scheme not found in registry")
	}

	cfg := &wire.SessionConfig{
		KEMScheme:          kemscheme,
		PKISignatureScheme: signSchemes.ByName(s.cfg.PKISignatureScheme),
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
	_, isAuthority := a.s.state.authorizedAuthorities[pk]

	if isMix || isGatewayNode || isServiceNode {
		a.isMix = true // Gateways and service nodes and mixes are all mixes.
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
