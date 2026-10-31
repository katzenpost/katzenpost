// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package directory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike"

	ps "github.com/katzenpost/katzenpost/pigeonservice"
)

// Client talks to one service directory. It is a ps.Discoverer, and with a
// service key a ps.Advertiser.
type Client struct {
	ph           ps.Pigeonhole
	node         ps.ServiceNode
	pub          nike.PublicKey
	key          *ps.ServiceKey
	pollInterval time.Duration

	mu  sync.Mutex
	seq uint64
}

var (
	_ ps.Advertiser = (*Client)(nil)
	_ ps.Discoverer = (*Client)(nil)
)

// ErrNoDirectory reports that the PKI lists no service directory.
var ErrNoDirectory = errors.New("directory: no service directory in the PKI")

// NewClient returns a client for the first directory in the PKI. key may be
// nil for a client that only looks services up.
func NewClient(ph ps.Pigeonhole, key *ps.ServiceKey, pollInterval time.Duration) (*Client, error) {
	nodes, err := ph.Services(ps.DirectoryCapability)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, ErrNoDirectory
	}
	return NewClientFor(ph, &nodes[0], key, pollInterval)
}

// NewClientFor returns a client for the directory at node.
func NewClientFor(ph ps.Pigeonhole, node *ps.ServiceNode, key *ps.ServiceKey, pollInterval time.Duration) (*Client, error) {
	pub, err := ps.PluginPublicKey(node, ps.DefaultNIKE)
	if err != nil {
		return nil, err
	}
	return &Client{ph: ph, node: *node, pub: pub, key: key, pollInterval: pollInterval}, nil
}

func (c *Client) request(ctx context.Context, req *ps.DirectoryRequest) (*ps.DirectoryReply, error) {
	payload, err := ps.Marshal(req)
	if err != nil {
		return nil, err
	}
	raw, err := c.ph.Request(ctx, &c.node.NodeIDHash, c.node.Endpoint, payload)
	if err != nil {
		return nil, err
	}
	var reply ps.DirectoryReply
	if err := ps.Unmarshal(raw, &reply); err != nil {
		return nil, err
	}
	if reply.Status != ps.StatusOK {
		return nil, &ps.StatusError{Status: reply.Status}
	}
	return &reply, nil
}

func (c *Client) nextSeq() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq = max(c.seq+1, uint64(time.Now().UnixNano()))
	return c.seq
}

// Advertise publishes d, replacing any earlier descriptor for its service.
func (c *Client) Advertise(ctx context.Context, d *ps.ServiceDescriptor) error {
	if c.key == nil {
		return errors.New("directory: advertising needs a service key")
	}
	if d.ID() != c.key.ID() {
		return errors.New("directory: descriptor is not this service's")
	}
	req := &ps.AdvertiseRequest{Descriptor: *d, Seq: c.nextSeq()}
	if err := c.key.SignAdvertise(c.pub, req); err != nil {
		return err
	}
	_, err := c.request(ctx, &ps.DirectoryRequest{Advertise: req})
	return err
}

// Withdraw removes this service's descriptor.
func (c *Client) Withdraw(ctx context.Context, id ps.ServiceID) error {
	if c.key == nil || id != c.key.ID() {
		return errors.New("directory: withdrawing needs the service's key")
	}
	req := &ps.WithdrawRequest{ServiceID: id, Seq: c.nextSeq()}
	if err := c.key.SignWithdraw(c.pub, req); err != nil {
		return err
	}
	_, err := c.request(ctx, &ps.DirectoryRequest{Withdraw: req})
	return err
}

// Lookup returns the descriptor of one service.
func (c *Client) Lookup(ctx context.Context, id ps.ServiceID) (*ps.ServiceDescriptor, error) {
	reply, err := c.request(ctx, &ps.DirectoryRequest{Lookup: &ps.LookupRequest{ServiceID: id}})
	if err != nil {
		return nil, err
	}
	if reply.Descriptor == nil || reply.Descriptor.ID() != id {
		return nil, errors.New("directory: reply names another service")
	}
	return reply.Descriptor, nil
}

// List returns every descriptor in the directory's current snapshot. If the
// snapshot is replaced while it is being read, List asks again.
func (c *Client) List(ctx context.Context) ([]ps.ServiceDescriptor, error) {
	for {
		descs, err := c.list(ctx)
		if !errors.Is(err, ps.ErrTombstone) {
			return descs, err
		}
	}
}

func (c *Client) list(ctx context.Context) ([]ps.ServiceDescriptor, error) {
	reply, err := c.request(ctx, &ps.DirectoryRequest{List: &ps.ListRequest{}})
	if err != nil {
		return nil, err
	}
	rc, err := bacap.ReadCapFromBytes(reply.ReadCap)
	if err != nil {
		return nil, err
	}
	start, err := bacap.NewEmptyMessageBoxIndexFromBytes(reply.StartIndex)
	if err != nil {
		return nil, err
	}
	snap, _, err := ps.ReadSnapshot(ctx, c.ph, rc, start, c.pollInterval)
	if err != nil {
		return nil, err
	}
	return snap.Descriptors, nil
}
