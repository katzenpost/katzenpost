// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package localnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/katzenpost/hpqc/rand"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	sphinxCommands "github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

// gateway is the network's one gateway. It runs the real wire protocol with
// clients and answers their consensus requests, and for each Sphinx packet
// does every hop's unwrap itself: the mixes are keys, not servers. Requests
// reach the service node's plugins at once and replies come back the same
// way, so the network adds no latency of its own.
type gateway struct {
	auth   *authority
	geo    *geo.Geometry
	sphinx *sphinx.Sphinx
	nodes  map[[32]byte]*node
	log    *logging.Logger

	ln net.Listener
	wg sync.WaitGroup

	nextID atomic.Uint64

	mu      sync.Mutex
	clients map[string]*clientConn
	plugins map[string]*hostedPlugin
	pending map[uint64][]byte // request ID -> SURB
	closed  bool
}

type clientConn struct {
	w   *wire.Session
	mu  sync.Mutex
	seq uint32
}

func newGateway(auth *authority, g *geo.Geometry, log *logging.Logger) (*gateway, error) {
	s, err := sphinx.FromGeometry(g)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &gateway{
		auth:    auth,
		geo:     g,
		sphinx:  s,
		nodes:   auth.nodes(),
		log:     log,
		ln:      ln,
		clients: make(map[string]*clientConn),
		plugins: make(map[string]*hostedPlugin),
		pending: make(map[uint64][]byte),
	}, nil
}

func (g *gateway) addr() string {
	return "tcp://" + g.ln.Addr().String()
}

func (g *gateway) start() {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for {
			conn, err := g.ln.Accept()
			if err != nil {
				return
			}
			g.wg.Add(1)
			go func() {
				defer g.wg.Done()
				g.serve(conn)
			}()
		}
	}()
}

func (g *gateway) close() {
	g.mu.Lock()
	g.closed = true
	for _, c := range g.clients {
		c.w.Close()
	}
	g.mu.Unlock()
	g.ln.Close()
	g.wg.Wait()
}

// IsPeerValid accepts every client: clients do not authenticate to a
// gateway.
func (g *gateway) IsPeerValid(*wire.PeerCredentials) bool { return true }

func (g *gateway) serve(conn net.Conn) {
	defer conn.Close()
	w, err := wire.NewSession(&wire.SessionConfig{
		KEMScheme:         wireKEM,
		Geometry:          g.geo,
		Authenticator:     g,
		AdditionalData:    g.auth.gateway.idHash[:],
		AuthenticationKey: g.auth.gateway.linkPriv,
		RandomReader:      rand.Reader,
	}, false)
	if err != nil {
		g.log.Errorf("wire session: %v", err)
		return
	}
	defer w.Close()
	if err := w.Initialize(context.Background(), conn); err != nil {
		g.log.Debugf("handshake: %v", err)
		return
	}
	creds, err := w.PeerCredentials()
	if err != nil {
		return
	}
	queue := string(creds.AdditionalData)
	c := &clientConn{w: w}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.clients[queue] = c
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		if g.clients[queue] == c {
			delete(g.clients, queue)
		}
		g.mu.Unlock()
	}()

	for {
		raw, err := w.RecvCommand(context.Background())
		if err != nil {
			return
		}
		switch cmd := raw.(type) {
		case *commands.NoOp, *commands.MessageDelivered:
		case *commands.GetConsensus2:
			if err := g.sendConsensus(c, cmd); err != nil {
				g.log.Debugf("sending consensus: %v", err)
				return
			}
		case *commands.SendPacket:
			pkt := bytes.Clone(cmd.SphinxPacket)
			g.wg.Add(1)
			go func() {
				defer g.wg.Done()
				if err := g.forward(pkt); err != nil {
					g.log.Warningf("dropping a packet: %v", err)
				}
			}()
		default:
			g.log.Warningf("unexpected command %T", cmd)
			return
		}
	}
}

func (c *clientConn) send(cmd commands.Command) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.w.SendCommand(context.Background(), cmd)
}

func (g *gateway) sendConsensus(c *clientConn, req *commands.GetConsensus2) error {
	_, signed, err := g.auth.document(req.Epoch)
	if err != nil {
		return c.send(&commands.Consensus2{Cmds: req.Cmds, ErrorCode: commands.ConsensusNotFound, ChunkTotal: 1})
	}
	chunks, err := pki.Chunk(signed, req.Cmds.MaxMessageLenServerToClient)
	if err != nil {
		return err
	}
	for i, chunk := range chunks {
		if err := c.send(&commands.Consensus2{
			Cmds:       req.Cmds,
			ErrorCode:  commands.ConsensusOk,
			ChunkNum:   uint32(i),
			ChunkTotal: uint32(len(chunks)),
			Payload:    chunk,
		}); err != nil {
			return err
		}
	}
	return nil
}

// unwrap does the Sphinx processing of every hop from first until the
// packet reaches its terminal hop, and returns that hop's payload and
// commands.
func (g *gateway) unwrap(first [32]byte, pkt []byte) ([]byte, []sphinxCommands.RoutingCommand, error) {
	hop := first
	for range g.geo.NrHops + 1 {
		n, ok := g.nodes[hop]
		if !ok {
			return nil, nil, fmt.Errorf("no node %x", hop[:8])
		}
		payload, _, cmds, err := g.sphinx.Unwrap(n.mixPriv, pkt)
		if err != nil {
			return nil, nil, fmt.Errorf("unwrap at %s: %w", n.desc.Name, err)
		}
		next := nextHop(cmds)
		if next == nil {
			return payload, cmds, nil
		}
		hop = *next
	}
	return nil, nil, errors.New("too many hops")
}

func nextHop(cmds []sphinxCommands.RoutingCommand) *[32]byte {
	for _, c := range cmds {
		if h, ok := c.(*sphinxCommands.NextNodeHop); ok {
			id := h.ID
			return &id
		}
	}
	return nil
}

func recipientOf(cmds []sphinxCommands.RoutingCommand) (string, bool) {
	for _, c := range cmds {
		if r, ok := c.(*sphinxCommands.Recipient); ok {
			return string(bytes.TrimRight(r.ID[:], "\x00")), true
		}
	}
	return "", false
}

func surbIDOf(cmds []sphinxCommands.RoutingCommand) (*[constants.SURBIDLength]byte, bool) {
	for _, c := range cmds {
		if s, ok := c.(*sphinxCommands.SURBReply); ok {
			id := s.ID
			return &id, true
		}
	}
	return nil, false
}

// forward carries a client's packet through every hop to the plugin it
// names.
func (g *gateway) forward(pkt []byte) error {
	payload, cmds, err := g.unwrap(g.auth.gateway.idHash, pkt)
	if err != nil {
		return err
	}
	recipient, ok := recipientOf(cmds)
	if !ok {
		return errors.New("terminal hop has no recipient")
	}
	ct, surb, err := parseForward(g.geo, payload)
	if err != nil {
		return err
	}
	g.mu.Lock()
	p, ok := g.plugins[recipient]
	g.mu.Unlock()
	if !ok {
		return fmt.Errorf("no service %q", recipient)
	}
	id := g.nextID.Add(1)
	if surb != nil {
		g.mu.Lock()
		g.pending[id] = surb
		g.mu.Unlock()
	}
	return p.plugin.OnCommand(&cborplugin.Request{ID: id, Payload: ct, SURB: surb})
}

// parseForward splits a forward payload into the user payload and the
// SURB, as a service node does.
func parseForward(g *geo.Geometry, b []byte) ([]byte, []byte, error) {
	hdr := g.SphinxPlaintextHeaderLength + g.SURBLength
	if len(b) != g.ForwardPayloadLength || len(b) < hdr {
		return nil, nil, fmt.Errorf("forward payload of %d bytes", len(b))
	}
	ct := b[hdr:]
	switch b[0] {
	case 0:
		return ct, nil, nil
	case 1:
		return ct, b[g.SphinxPlaintextHeaderLength:hdr], nil
	default:
		return nil, nil, fmt.Errorf("forward payload flags 0x%02x", b[0])
	}
}

// reply carries a plugin's response back to the client along its SURB.
func (g *gateway) reply(cmd cborplugin.Command) {
	r, ok := cmd.(*cborplugin.Response)
	if !ok || r.IsParametersResponse {
		return
	}
	g.mu.Lock()
	surb, ok := g.pending[r.ID]
	delete(g.pending, r.ID)
	g.mu.Unlock()
	if !ok {
		return
	}
	if err := g.deliverReply(surb, r.Payload); err != nil {
		g.log.Warningf("dropping a reply: %v", err)
	}
}

func (g *gateway) deliverReply(surb, payload []byte) error {
	if len(payload) > g.geo.ForwardPayloadLength {
		return fmt.Errorf("reply of %d bytes", len(payload))
	}
	padded := make([]byte, g.geo.ForwardPayloadLength)
	copy(padded, payload)
	pkt, first, err := g.sphinx.NewPacketFromSURB(surb, padded)
	if err != nil {
		return err
	}
	body, cmds, err := g.unwrap(*first, pkt)
	if err != nil {
		return err
	}
	recipient, ok := recipientOf(cmds)
	if !ok {
		return errors.New("reply has no recipient")
	}
	surbID, ok := surbIDOf(cmds)
	if !ok {
		return errors.New("reply has no SURB ID")
	}
	g.mu.Lock()
	c, ok := g.clients[recipient]
	g.mu.Unlock()
	if !ok {
		return fmt.Errorf("no client %q", recipient)
	}
	c.mu.Lock()
	c.seq++
	seq := c.seq
	c.mu.Unlock()
	msg := &commands.Message{
		Geo:      g.geo,
		Cmds:     commands.NewMixnetCommands(g.geo),
		Sequence: seq,
		SURBID:   *surbID,
		Payload:  body,
	}
	return c.send(msg)
}
