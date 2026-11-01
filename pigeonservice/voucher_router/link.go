// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher_router

import (
	"context"
	"errors"
	"time"

	"github.com/katzenpost/hpqc/protocols/sealedbox"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// ErrNoRouter reports that no router accepted a request.
var ErrNoRouter = errors.New("pigeonservice: no voucher router accepted the request")

// Register opens a link between a service and the voucher router at node,
// leased until expiry (see common.LeaseExpiry). The service mints a
// voucher, registers it with the router, and waits for the router's
// induction. The returned Conn is the service's end: it reads the vouchers
// the router forwards.
func Register(ctx context.Context, ph common.Pigeonhole, key *common.ServiceKey, node *common.ServiceNode, pollInterval time.Duration, expiry uint64) (*Conn, error) {
	routerPub, err := common.PluginPublicKey(node, key.Scheme)
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
		Seq:        common.NextSeq(),
		Expiry:     expiry,
	}
	if err := SignRegister(key, routerPub, req); err != nil {
		return nil, err
	}
	if _, err := serviceRequest(ctx, ph, node, &RouterRequest{Register: req}); err != nil {
		return nil, err
	}
	return pending.Await(ctx, ph, pollInterval)
}

// Renew moves the expiry of the service's link with the router at node.
func Renew(ctx context.Context, ph common.Pigeonhole, key *common.ServiceKey, node *common.ServiceNode, expiry uint64) error {
	routerPub, err := common.PluginPublicKey(node, key.Scheme)
	if err != nil {
		return err
	}
	req := &RenewRequest{NIKEScheme: key.Scheme.Name(), PublicKey: key.Public.Bytes(), Seq: common.NextSeq(), Expiry: expiry}
	if err := SignRenew(key, routerPub, req); err != nil {
		return err
	}
	_, err = serviceRequest(ctx, ph, node, &RouterRequest{Renew: req})
	return err
}

// Unregister closes the service's link with the router at node.
func Unregister(ctx context.Context, ph common.Pigeonhole, key *common.ServiceKey, node *common.ServiceNode) error {
	routerPub, err := common.PluginPublicKey(node, key.Scheme)
	if err != nil {
		return err
	}
	req := &UnregisterRequest{NIKEScheme: key.Scheme.Name(), PublicKey: key.Public.Bytes(), Seq: common.NextSeq()}
	if err := SignUnregister(key, routerPub, req); err != nil {
		return err
	}
	_, err = serviceRequest(ctx, ph, node, &RouterRequest{Unregister: req})
	return err
}

func serviceRequest(ctx context.Context, ph common.Pigeonhole, node *common.ServiceNode, req *RouterRequest) (*RouterReply, error) {
	payload, err := common.Marshal(req)
	if err != nil {
		return nil, err
	}
	return routerRequest(ctx, ph, &node.NodeIDHash, node.Endpoint, payload)
}

func routerRequest(ctx context.Context, ph common.Pigeonhole, node *[32]byte, endpoint, payload []byte) (*RouterReply, error) {
	raw, err := ph.Request(ctx, node, endpoint, payload)
	if err != nil {
		return nil, err
	}
	var reply RouterReply
	if err := common.Unmarshal(raw, &reply); err != nil {
		return nil, err
	}
	if reply.Status != common.StatusOK {
		return nil, &common.StatusError{Status: reply.Status}
	}
	return &reply, nil
}

// routeTimeout is how long Route waits for one router before trying the
// next.
const routeTimeout = 5 * time.Minute

// Route seals voucher to the service d describes and hands it to one of the
// service's routers, trying each in turn until one accepts it. Only routers
// the PKI lists are tried: descriptors come from untrusted directories.
func Route(ctx context.Context, ph common.Pigeonhole, d *common.ServiceDescriptor, voucher []byte) error {
	nodes, err := ph.Services(RouterCapability)
	if err != nil {
		return err
	}
	inPKI := make(map[common.RouterRef]bool, len(nodes))
	for _, n := range nodes {
		inPKI[common.RouterRef{NodeIDHash: n.NodeIDHash, Endpoint: string(n.Endpoint)}] = true
	}
	sealed, err := ph.BoxSeal(d.NIKEScheme, d.PublicKey, voucher)
	if err != nil {
		return err
	}
	payload, err := common.Marshal(&RouterRequest{Route: &RouteRequest{ServiceID: d.ID(), Ciphertext: sealed}})
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
		_, err := routerRequest(rctx, ph, &r.NodeIDHash, []byte(r.Endpoint), payload)
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

// OpenForward opens a sealed voucher a router forwarded over a link, as the
// service whose key opens it.
func OpenForward(key *common.ServiceKey, msg []byte) ([]byte, error) {
	var lm LinkMessage
	if err := common.Unmarshal(msg, &lm); err != nil {
		return nil, err
	}
	if len(lm.Forward) == 0 {
		return nil, errors.New("pigeonservice: empty link message")
	}
	return sealedbox.NewScheme(key.Scheme).Open(key.Private, key.Public, lm.Forward)
}
