// mixkey.go - Katzenpost server mix key store.
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

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/server/internal/mixkey"
	"github.com/op/go-logging"
)

const numMixKeys = 3

type mixKeys struct {
	sync.Mutex

	s   *Server
	log *logging.Logger

	keys map[uint64]*mixkey.MixKey
}

func (m *mixKeys) init() error {
	// Generate/load the initial set of keys.
	//
	// TODO: In theory this should also try to load the previous epoch's key
	// if the current time is in the clock skew grace period.  But it may not
	// matter much in practice.
	epoch, _, _ := epochtime.Now()
	if _, err := m.generateMixKeys(epoch); err != nil {
		return err
	}

	// Clean up stale mix keys hanging around the data directory.
	files, err := filepath.Glob(filepath.Join(m.s.cfg.Server.DataDir, mixkey.KeyGlob))
	if err != nil {
		m.log.Warningf("Failed to find persisted keys: %v", err)
	}
	keyFmt := filepath.Join(m.s.cfg.Server.DataDir, mixkey.KeyFmt)
	for _, f := range files {
		e := uint64(0)
		if _, err := fmt.Sscanf(f, keyFmt, &e); err != nil {
			m.log.Debugf("Failed to extract epoch from '%v': %v", f, err)
			continue
		}
		if _, ok := m.keys[e]; !ok && e < epoch {
			m.log.Debugf("Purging stale key: %v", f)
			os.Remove(f)
		}
	}

	return nil
}

func (m *mixKeys) generateMixKeys(baseEpoch uint64) (bool, error) {
	didGenerate := false

	m.Lock()
	defer m.Unlock()
	for e := baseEpoch; e < baseEpoch+numMixKeys; e++ {
		// Skip keys that we already have.
		if _, ok := m.keys[e]; ok {
			continue
		}

		didGenerate = true
		k, err := mixkey.New(m.s.cfg.Server.DataDir, e)
		if err != nil {
			// Clean up whatever keys that may have succeded.
			for ee := baseEpoch; ee < baseEpoch+numMixKeys; ee++ {
				if kk, ok := m.keys[ee]; ok {
					kk.Deref()
					delete(m.keys, ee)
				}
			}
			return false, err
		}
		k.SetUnlinkIfExpired(true)
		m.keys[e] = k
	}

	return didGenerate, nil
}

func (m *mixKeys) pruneMixKeys() bool {
	epoch, _, _ := epochtime.Now()
	didPrune := false

	m.Lock()
	defer m.Unlock()

	for idx, v := range m.keys {
		if idx < epoch {
			m.log.Debugf("Purging expired key for epoch: %v", idx)
			v.Deref()
			delete(m.keys, idx)
			didPrune = true
		}
	}

	return didPrune
}

func (m *mixKeys) shadow(dst map[uint64]*mixkey.MixKey) {
	m.Lock()
	defer m.Unlock()

	// Purge the keys no longer listed from dst.
	for k, v := range dst {
		if _, ok := m.keys[k]; !ok {
			v.Deref()
			delete(dst, k)
		}
	}

	// Add newly listed keys to dst and bump up the refcount.
	for k, v := range m.keys {
		if _, ok := dst[k]; !ok {
			v.Ref()
			dst[k] = v
		}
	}
}

func (m *mixKeys) Halt() {
	m.Lock()
	defer m.Unlock()

	for k, v := range m.keys {
		v.Deref()
		delete(m.keys, k)
	}
}

func newMixKeys(s *Server) (*mixKeys, error) {
	m := new(mixKeys)
	m.s = s
	m.log = s.logBackend.GetLogger("mixkeys")
	m.keys = make(map[uint64]*mixkey.MixKey)
	if err := m.init(); err != nil {
		return nil, err
	}

	return m, nil
}
