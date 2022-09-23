// pkiclient.go - Caching PKI client.
// Copyright (C) 2017  Yawning Angel.
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

// Package pkiclient implements a caching wrapper around core/pki.Client.
package pkiclient

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
)

var (
	errNotSupported = errors.New("pkiclient: operation not supported")
	errHalted       = errors.New("pkiclient: client was halted")

	fetchBacklog = 8
	lruMaxSize   = 8
)

type cacheEntry struct {
	raw []byte
	doc *pki.Document
}

// Client is a caching PKI client.
type Client struct {
	sync.Mutex
	worker.Worker

	impl pki.Client
	docs map[uint64]*list.Element
	lru  list.List

	fetchQueue chan *fetchOp
}

type fetchOp struct {
	ctx    context.Context
	epoch  uint64
	doneCh chan interface{}
}

// Halt tears down the Client instance.
func (c *Client) Halt() {
	c.Worker.Halt()

	// Clean out c.fetchQueue.
	for {
		select {
		case op := <-c.fetchQueue:
			op.doneCh <- errHalted
		default:
			return
		}
	}
}

// Get returns the PKI document for the provided epoch.
func (c *Client) Get(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	// Fast path, cache hit.
	if d := c.cacheGet(epoch); d != nil {
		return d.doc, d.raw, nil
	}

	op := &fetchOp{
		ctx:    ctx,
		epoch:  epoch,
		doneCh: make(chan interface{}),
	}
	select {
	case c.fetchQueue <- op:
	case <-c.HaltCh():
		return nil, nil, errHalted
	}
	select {
	case v := <-op.doneCh:
		switch r := v.(type) {
		case error:
			return nil, nil, r
		case *cacheEntry:
			// Worker will handle the LRU.
			return r.doc, r.raw, nil
		default:
			return nil, nil, fmt.Errorf("BUG: pkiclient: worker returned nonsensical result: %+v", r)
		}
	case <-c.HaltCh():
		return nil, nil, errHalted
	}
}

// Post posts the node's descriptor to the PKI for the provided epoch.
func (c *Client) Post(ctx context.Context, epoch uint64, signingKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.MixDescriptor) error {
	return errNotSupported
}

// Deserialize returns PKI document given the raw bytes.
func (c *Client) Deserialize(raw []byte) (*pki.Document, error) {
	return c.impl.Deserialize(raw) // I hope impl.Deserialize is re-entrant.
}

func (c *Client) cacheGet(epoch uint64) *cacheEntry {
	c.Lock()
	defer c.Unlock()

	if e, ok := c.docs[epoch]; ok {
		c.lru.MoveToFront(e)
		return e.Value.(*cacheEntry)
	}
	return nil
}

func (c *Client) insertLRU(newEntry *cacheEntry) {
	c.Lock()
	defer c.Unlock()

	e := c.lru.PushFront(newEntry)
	c.docs[newEntry.doc.Epoch] = e

	// Enforce the max size, by purging based off the LRU.
	for c.lru.Len() > lruMaxSize {
		e = c.lru.Back()
		d := e.Value.(*cacheEntry)

		delete(c.docs, d.doc.Epoch)
		c.lru.Remove(e)
	}
}

func (c *Client) worker() {
	for {
		var op *fetchOp
		select {
		case <-c.HaltCh():
			return
		case op = <-c.fetchQueue:
		}

		// The fetch may have been in progress while the op was sitting in
		// queue, check again.
		if d := c.cacheGet(op.epoch); d != nil {
			select {
			case <-c.HaltCh():
				return
			case op.doneCh <- d:
				continue
			}
		}

		// Slow path, have to call into the PKI client.
		//
		// TODO: This could allow concurrent fetches at some point, but for
		// most common client use cases, this shouldn't matter much.
		d, raw, err := c.impl.Get(op.ctx, op.epoch)
		if err != nil {
			select {
			case <-c.HaltCh():
				return
			case op.doneCh <- err:
				continue
			}
		}
		e := &cacheEntry{doc: d, raw: raw}
		c.insertLRU(e)
		select {
		case <-c.HaltCh():
			return
		case op.doneCh <- e:
		}
	}
}

// New constructs a new Client backed by an existing pki.Client instance.
func New(impl pki.Client) *Client {
	c := new(Client)
	c.impl = impl
	c.docs = make(map[uint64]*list.Element)
	c.fetchQueue = make(chan *fetchOp, fetchBacklog)

	c.Go(c.worker)
	return c
}
