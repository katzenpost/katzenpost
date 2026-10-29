// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/protocols/sealedbox"
)

// ErrNoRouter reports that no router accepted a request.
var ErrNoRouter = errors.New("pigeonservice: no voucher router accepted the request")

// StatusError is a non-OK status from a router or a directory.
type StatusError struct {
	Status uint8
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("pigeonservice: status %d", e.Status)
}

// Register opens a link between a service and the voucher router at node.
// The service mints a voucher, registers it with the router, and waits for
// the router's induction. The returned Conn is the service's end: it reads
// the vouchers the router forwards.
func Register(ctx context.Context, ph Pigeonhole, key *ServiceKey, node *ServiceNode, pollInterval time.Duration) (*Conn, error) {
	routerPub, err := PluginPublicKey(node, key.Scheme)
	if err != nil {
		return nil, err
	}
	pending, err := Mint(ctx, ph, "service")
	if err != nil {
		return nil, err
	}
	req := &RegisterRequest{
		NIKEScheme: key.Scheme.Name(),
		PublicKey:  key.Public.Bytes(),
		Voucher:    pending.Voucher,
	}
	if err := key.SignRegister(routerPub, req); err != nil {
		return nil, err
	}
	payload, err := Marshal(&RouterRequest{Register: req})
	if err != nil {
		return nil, err
	}
	if err := routerRequest(ctx, ph, &node.NodeIDHash, node.Endpoint, payload); err != nil {
		return nil, err
	}
	return pending.Await(ctx, ph, pollInterval)
}

func routerRequest(ctx context.Context, ph Pigeonhole, node *[32]byte, endpoint, payload []byte) error {
	raw, err := ph.Request(ctx, node, endpoint, payload)
	if err != nil {
		return err
	}
	var reply RouterReply
	if err := Unmarshal(raw, &reply); err != nil {
		return err
	}
	if reply.Status != StatusOK {
		return &StatusError{Status: reply.Status}
	}
	return nil
}

// routeTimeout is how long Route waits for one router before trying the
// next.
const routeTimeout = 5 * time.Minute

// Route seals voucher to the service d describes and hands it to one of the
// service's routers, trying each in turn until one accepts it. Only routers
// the PKI lists are tried: descriptors come from untrusted directories.
func Route(ctx context.Context, ph Pigeonhole, d *ServiceDescriptor, voucher []byte) error {
	nodes, err := ph.Services(RouterCapability)
	if err != nil {
		return err
	}
	inPKI := make(map[RouterRef]bool, len(nodes))
	for _, n := range nodes {
		inPKI[RouterRef{NodeIDHash: n.NodeIDHash, Endpoint: string(n.Endpoint)}] = true
	}
	sealed, err := ph.BoxSeal(d.NIKEScheme, d.PublicKey, voucher)
	if err != nil {
		return err
	}
	payload, err := Marshal(&RouterRequest{Route: &RouteRequest{ServiceID: d.ID(), Ciphertext: sealed}})
	if err != nil {
		return err
	}
	lastErr := ErrNoRouter
	for i := range d.Routers {
		r := &d.Routers[i]
		if !inPKI[*r] {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, routeTimeout)
		err := routerRequest(rctx, ph, &r.NodeIDHash, []byte(r.Endpoint), payload)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		lastErr = err
	}
	return lastErr
}

// openForward opens a sealed voucher a router forwarded.
func openForward(key *ServiceKey, msg []byte) ([]byte, error) {
	var lm LinkMessage
	if err := Unmarshal(msg, &lm); err != nil {
		return nil, err
	}
	if len(lm.Forward) == 0 {
		return nil, errors.New("pigeonservice: empty link message")
	}
	return sealedbox.NewScheme(key.Scheme).Open(key.Private, key.Public, lm.Forward)
}
