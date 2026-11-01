// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// Client talks to one service directory. It is a Discoverer, and with a
// service key a Advertiser.
type Client struct {
	ph           common.Pigeonhole
	node         common.ServiceNode
	pub          nike.PublicKey
	key          *common.ServiceKey
	pollInterval time.Duration

	mu  sync.Mutex
	seq uint64
}

var (
	_ Advertiser = (*Client)(nil)
	_ Discoverer = (*Client)(nil)
)

// ErrNoDirectory reports that the PKI lists no service directory.
var ErrNoDirectory = errors.New("directory: no service directory in the PKI")

// NewClient returns a client for the first directory in the PKI. key may be
// nil for a client that only looks services up.
func NewClient(ph common.Pigeonhole, key *common.ServiceKey, pollInterval time.Duration) (*Client, error) {
	nodes, err := ph.Services(DirectoryCapability)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, ErrNoDirectory
	}
	return NewClientFor(ph, &nodes[0], key, pollInterval)
}

// NewClientFor returns a client for the directory at node.
func NewClientFor(ph common.Pigeonhole, node *common.ServiceNode, key *common.ServiceKey, pollInterval time.Duration) (*Client, error) {
	pub, err := common.PluginPublicKey(node, common.DefaultNIKE)
	if err != nil {
		return nil, err
	}
	return &Client{ph: ph, node: *node, pub: pub, key: key, pollInterval: pollInterval}, nil
}

func (c *Client) request(ctx context.Context, req *DirectoryRequest) (*DirectoryReply, error) {
	payload, err := common.Marshal(req)
	if err != nil {
		return nil, err
	}
	raw, err := c.ph.Request(ctx, &c.node.NodeIDHash, c.node.Endpoint, payload)
	if err != nil {
		return nil, err
	}
	var reply DirectoryReply
	if err := common.Unmarshal(raw, &reply); err != nil {
		return nil, err
	}
	if reply.Status != common.StatusOK {
		return nil, &common.StatusError{Status: reply.Status}
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
func (c *Client) Advertise(ctx context.Context, d *common.ServiceDescriptor) error {
	if c.key == nil {
		return errors.New("directory: advertising needs a service key")
	}
	if d.ID() != c.key.ID() {
		return errors.New("directory: descriptor is not this service's")
	}
	req := &AdvertiseRequest{Descriptor: *d, Seq: c.nextSeq()}
	if err := SignAdvertise(c.key, c.pub, req); err != nil {
		return err
	}
	_, err := c.request(ctx, &DirectoryRequest{Advertise: req})
	return err
}

// Withdraw removes this service's descriptor.
func (c *Client) Withdraw(ctx context.Context, id common.ServiceID) error {
	if c.key == nil || id != c.key.ID() {
		return errors.New("directory: withdrawing needs the service's key")
	}
	req := &WithdrawRequest{ServiceID: id, Seq: c.nextSeq()}
	if err := SignWithdraw(c.key, c.pub, req); err != nil {
		return err
	}
	_, err := c.request(ctx, &DirectoryRequest{Withdraw: req})
	return err
}

// Lookup returns the descriptor of one service.
func (c *Client) Lookup(ctx context.Context, id common.ServiceID) (*common.ServiceDescriptor, error) {
	reply, err := c.request(ctx, &DirectoryRequest{Lookup: &LookupRequest{ServiceID: id}})
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
func (c *Client) List(ctx context.Context) ([]common.ServiceDescriptor, error) {
	for {
		descs, err := c.list(ctx)
		if !errors.Is(err, common.ErrTombstone) {
			return descs, err
		}
	}
}

func (c *Client) list(ctx context.Context) ([]common.ServiceDescriptor, error) {
	reply, err := c.request(ctx, &DirectoryRequest{List: &ListRequest{}})
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
	snap, _, err := ReadSnapshot(ctx, c.ph, rc, start, c.pollInterval)
	if err != nil {
		return nil, err
	}
	return snap.Descriptors, nil
}
