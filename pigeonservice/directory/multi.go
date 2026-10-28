// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package directory

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"time"

	ps "github.com/katzenpost/katzenpost/pigeonservice"
)

// All talks to every service directory in the PKI. Directories do not share
// what they hold, so a service advertises to all of them and a client asks
// each in turn.
type All struct {
	clients []*Client
}

var (
	_ ps.Advertiser = (*All)(nil)
	_ ps.Discoverer = (*All)(nil)
)

// NewAll returns a client for every directory in the PKI. key may be nil for
// a client that only looks services up.
func NewAll(ph ps.Pigeonhole, key *ps.ServiceKey, pollInterval time.Duration) (*All, error) {
	nodes, err := ph.Services(ps.DirectoryCapability)
	if err != nil {
		return nil, err
	}
	a := &All{}
	for i := range nodes {
		c, err := NewClientFor(ph, &nodes[i], key, pollInterval)
		if err != nil {
			continue
		}
		a.clients = append(a.clients, c)
	}
	if len(a.clients) == 0 {
		return nil, ErrNoDirectory
	}
	return a, nil
}

// Advertise publishes d at every directory. It fails only if no directory
// took it.
func (a *All) Advertise(ctx context.Context, d *ps.ServiceDescriptor) error {
	var errs []error
	for _, c := range a.clients {
		if err := c.Advertise(ctx, d); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == len(a.clients) {
		return errors.Join(errs...)
	}
	return nil
}

// Withdraw removes the service's descriptor from every directory.
func (a *All) Withdraw(ctx context.Context, id ps.ServiceID) error {
	var errs []error
	for _, c := range a.clients {
		if err := c.Withdraw(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == len(a.clients) {
		return errors.Join(errs...)
	}
	return nil
}

// Lookup asks each directory in turn until one knows the service.
func (a *All) Lookup(ctx context.Context, id ps.ServiceID) (*ps.ServiceDescriptor, error) {
	var errs []error
	for _, c := range a.clients {
		d, err := c.Lookup(ctx, id)
		if err == nil {
			return d, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// List merges every directory's snapshot, keeping for each service the
// descriptor that lists the most routers.
func (a *All) List(ctx context.Context) ([]ps.ServiceDescriptor, error) {
	best := map[ps.ServiceID]ps.ServiceDescriptor{}
	var errs []error
	for _, c := range a.clients {
		descs, err := c.List(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			errs = append(errs, err)
			continue
		}
		for _, d := range descs {
			if old, ok := best[d.ID()]; !ok || len(d.Routers) > len(old.Routers) {
				best[d.ID()] = d
			}
		}
	}
	if len(errs) == len(a.clients) {
		return nil, errors.Join(errs...)
	}
	all := make([]ps.ServiceDescriptor, 0, len(best))
	for _, d := range best {
		all = append(all, d)
	}
	sort.Slice(all, func(i, j int) bool {
		x, y := all[i].ID(), all[j].ID()
		return bytes.Compare(x[:], y[:]) < 0
	})
	return all, nil
}
