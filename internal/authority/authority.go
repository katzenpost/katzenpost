// authority.go - Authority interface.
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

// Package authority implements the generic PKI backend.
package authority

import (
	"errors"
	"sync"

	"github.com/katzenpost/client/internal/pkiclient"
	"github.com/katzenpost/client/internal/proxy"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
)

var (
	errInvalidID       = errors.New("authority: invalid identifier")
	errNoSuchAuthority = errors.New("authority: no such authority")
	errExists          = errors.New("authority: provided id/authority already exists")
)

// Factory constructs a new pki.Client instance with a pre-set configuration.
type Factory interface {
	New(*log.Backend, *proxy.Config) (pki.Client, error)
}

// Authority is a directory authority instance.
type Authority struct {
	s        *Store
	id       string
	impl     *pkiclient.Client
	refCount int32
}

func (a *Authority) doDeref() {
	// Note: This assumes the Store lock is held.

	a.refCount--
	switch {
	case a.refCount == 0:
		delete(a.s.authorities, a.id)
		a.impl.Halt()
	case a.refCount < 0:
		panic("BUG: authority: refcount is negative: " + a.id)
	default:
	}
}

// Client returns the pki.Client instance associated with the Authority.
func (a *Authority) Client() pki.Client {
	return a.impl
}

// Deref decrements the reference count of the Authority.  If the reference
// count reaches 0, the Authority will be torn down and removed from it's
// associated Store.
func (a *Authority) Deref() {
	a.s.Lock()
	defer a.s.Unlock()

	a.doDeref()
}

// Store is a group of Authority instances.
type Store struct {
	sync.Mutex

	logBackend  *log.Backend
	proxyConfig *proxy.Config
	authorities map[string]*Authority
}

// Set sets the Authority identified by id, to a new pki.Client constructed
// by the provided factory f, wrapped in a caching wrapper.
func (s *Store) Set(id string, f Factory) error {
	if id == "" {
		return errInvalidID
	}

	s.Lock()
	defer s.Unlock()

	if _, ok := s.authorities[id]; ok {
		return errExists
	}

	impl, err := f.New(s.logBackend, s.proxyConfig)
	if err != nil {
		return err
	}

	a := new(Authority)
	a.s = s
	a.id = id
	a.impl = pkiclient.New(impl)
	a.refCount = 1 // Store holds a reference.
	s.authorities[id] = a

	return nil
}

// Get returns the Authority identified by id, after incrementing the reference
// count.
func (s *Store) Get(id string) (*Authority, error) {
	s.Lock()
	defer s.Unlock()

	if id == "" {
		return nil, errNoSuchAuthority
	}

	if a, ok := s.authorities[id]; ok {
		a.refCount++
		return a, nil
	}
	return nil, errNoSuchAuthority
}

// Reset clears the Store after Deref()ing each Authority.  If any Authority
// has any other existing references, this call will panic.
func (s *Store) Reset() {
	s.Lock()
	defer s.Unlock()

	for id, v := range s.authorities {
		v.doDeref()
		if v.refCount != 0 {
			panic("BUG: authority: Authority has non-zero refcount: " + id)
		}
	}
}

// NewStore constructs a new Store instance.
func NewStore(l *log.Backend, pCfg *proxy.Config) *Store {
	s := new(Store)
	s.logBackend = l
	s.proxyConfig = pCfg
	s.authorities = make(map[string]*Authority)
	return s
}
