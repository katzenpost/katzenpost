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

package mixkeys

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/internal/constants"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/mixkey"
)

// keyFileRe matches persisted mix key file names written by the mixkey
// package, capturing the epoch.
var keyFileRe = regexp.MustCompile(`^mixkey-(\d+)\.bin$`)

type mixKeys struct {
	sync.Mutex

	geo  *geo.Geometry
	glue glue.Glue
	log  *logging.Logger

	keys map[uint64]*mixkey.MixKey

	nike nike.Scheme
	kem  kem.Scheme

	// persistOnShutdown, when enabled, writes every live mix key to
	// keyStoreDir on clean shutdown and reloads them on boot, so a clean
	// restart keeps the keypairs already published in the consensus.
	persistOnShutdown bool
	keyStoreDir       string
}

func (m *mixKeys) init() error {
	// Generate/load the initial set of keys.
	//
	// TODO: In theory this should also try to load the previous epoch's key
	// if the current time is in the clock skew grace period.  But it may not
	// matter much in practice.
	epoch, _, _ := epochtime.Now()
	if err := m.purgeStaleKeyFiles(epoch); err != nil {
		return err
	}
	if _, err := m.Generate(epoch); err != nil {
		return err
	}

	return nil
}

// purgeStaleKeyFiles removes persisted mix key files for epochs that are no
// longer part of the current generation window. With a durable keyStoreDir
// (e.g. a docker testnet bind-mount), files written by a clean shutdown can
// outlive their usefulness when the node comes back up many epochs later.
// Prune only removes files for keys that are still live in m.keys, so the
// sweep happens here on boot. Consume-on-read in mixkey.Load already removes
// in-window files the moment they are loaded; everything else that matches
// the key file pattern and predates the window is stale.
func (m *mixKeys) purgeStaleKeyFiles(baseEpoch uint64) error {
	if !m.persistOnShutdown {
		return nil
	}

	entries, err := os.ReadDir(m.keyStoreDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, ent := range entries {
		name := ent.Name()
		sub := keyFileRe.FindStringSubmatch(name)
		if sub == nil {
			continue
		}
		e, err := strconv.ParseUint(sub[1], 10, 64)
		if err != nil {
			continue
		}
		if e < baseEpoch || e >= baseEpoch+constants.NumMixKeys {
			m.log.Noticef("Purging stale persisted mix key for epoch %d", e)
			if err := os.Remove(filepath.Join(m.keyStoreDir, name)); err != nil {
				m.log.Warningf("Failed to purge stale persisted mix key for epoch %d: %v", e, err)
			}
		}
	}

	return nil
}

func (m *mixKeys) Generate(baseEpoch uint64) (bool, error) {
	didGenerate := false

	m.Lock()
	defer m.Unlock()
	for e := baseEpoch; e < baseEpoch+constants.NumMixKeys; e++ {
		// Skip keys that we already have.
		if _, ok := m.keys[e]; ok {
			continue
		}

		didGenerate = true
		var (
			k     *mixkey.MixKey
			found bool
			err   error
		)
		if m.persistOnShutdown {
			k, found, err = mixkey.Load(e, m.geo, m.keyStoreDir)
			if err != nil {
				// A persisted key file that cannot be loaded or consumed
				// is fatal: the on-disk state disagrees with what the
				// consensus expects, and silently generating a fresh key
				// would leave the node out of sync (first-hop MAC
				// failures) until the next epoch. Refuse to start so the
				// operator sees the cause.
				m.log.Errorf("Failed to load persisted mix key for epoch %d: %v", e, err)
				return false, err
			} else if found {
				m.log.Debugf("Loaded persisted mix key for epoch %d", e)
			}
		}
		if k == nil {
			k, err = mixkey.New(e, m.geo)
			if err != nil {
				// Clean up whatever keys that may have succeeded.
				for ee := baseEpoch; ee < baseEpoch+constants.NumMixKeys; ee++ {
					if kk, ok := m.keys[ee]; ok {
						kk.Deref()
						delete(m.keys, ee)
					}
				}
				return false, err
			}
		}
		k.SetUnlinkIfExpired(true)
		m.keys[e] = k
	}

	return didGenerate, nil
}

func (m *mixKeys) Prune() bool {
	epoch, _, _ := epochtime.Now()
	didPrune := false

	m.Lock()
	defer m.Unlock()

	for idx, v := range m.keys {
		if idx < epoch-1 {
			m.log.Debugf("Purging expired key for epoch: %v", idx)
			v.Deref()
			delete(m.keys, idx)
			if m.persistOnShutdown {
				mixkey.Remove(idx, m.keyStoreDir)
			}
			didPrune = true
		}
	}

	return didPrune
}

func (m *mixKeys) Get(epoch uint64) ([]byte, bool) {
	m.Lock()
	defer m.Unlock()

	if k, ok := m.keys[epoch]; ok {
		return k.PublicBytes(), true
	}
	return nil, false
}

func (m *mixKeys) Shadow(dst map[uint64]*mixkey.MixKey) {
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
		if m.persistOnShutdown {
			if err := v.Persist(m.keyStoreDir); err != nil {
				m.log.Warningf("Failed to persist mix key for epoch %d on shutdown: %v", v.Epoch(), err)
			} else {
				m.log.Noticef("Persisted mix key for epoch %d to %s", v.Epoch(), m.keyStoreDir)
			}
		}
		v.Deref()
		delete(m.keys, k)
	}
}

func NewMixKeys(glue glue.Glue, geo *geo.Geometry) (glue.MixKeys, error) {
	m := &mixKeys{
		geo:  geo,
		glue: glue,
		log:  glue.LogBackend().GetLogger("mixkeys"),
		keys: make(map[uint64]*mixkey.MixKey),
	}

	if glue.Config().Server.PersistMixKeysOnShutdown {
		m.persistOnShutdown = true
		if dir := glue.Config().Server.PersistMixKeysOnShutdownDir; dir != "" {
			m.keyStoreDir = dir
		} else {
			m.keyStoreDir = defaultKeyStoreDir(glue.IdentityPublicKey())
		}
	}

	if err := m.init(); err != nil {
		return nil, err
	}

	return m, nil
}

// defaultKeyStoreDir returns the tmpfs subdirectory used for persisted mix
// keys when no explicit directory is configured: a per-node path derived
// from a hash of the node's long-term identity key, so key material
// survives a clean daemon restart but never touches durable storage.
// Persist on shutdown and the consume-on-read boot reload then only span
// the daemon's own lifetime.
func defaultKeyStoreDir(idKey sign.PublicKey) string {
	idKeyHash := hash.Sum256From(idKey)
	return filepath.Join("/dev/shm", fmt.Sprintf("katzenpost-mixkeys-%x", idKeyHash))
}
