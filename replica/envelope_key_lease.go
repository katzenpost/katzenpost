// SPDX-License-Identifier: AGPL-3.0-only
package replica

import (
	"errors"
	"sync"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// envelopeKeyUse is protected by keysLock. Retired keys are no longer
// discoverable, but their private material remains live until the last
// admitted request finishes. Request decapsulation, proxy waits, and reply
// sealing run without holding the key-map lock.
type envelopeKeyUse struct {
	users   int
	retired bool
}

// envelopeKeyLease owns one use of a shared key through reply sealing.
// Release is required on every successful acquisition and is idempotent.
type envelopeKeyLease struct {
	*replicaCommon.EnvelopeKey
	owner *EnvelopeKeys
	once  sync.Once
}

func (k *EnvelopeKeys) acquireKey(replicaEpoch uint64) (*envelopeKeyLease, error) {
	k.keysLock.Lock()
	defer k.keysLock.Unlock()
	key := k.keys[replicaEpoch]
	if key == nil {
		return nil, errors.New("key for given replica epoch doesn't exist")
	}
	if k.leases == nil {
		k.leases = make(map[*replicaCommon.EnvelopeKey]*envelopeKeyUse)
	}
	use := k.leases[key]
	if use == nil {
		use = &envelopeKeyUse{}
		k.leases[key] = use
	}
	use.users++
	return &envelopeKeyLease{EnvelopeKey: key, owner: k}, nil
}

// retireKeyLocked is called while holding keysLock exclusively. It never
// waits for requests: acquisition stops when the caller removes/replaces keys.
func (k *EnvelopeKeys) retireKeyLocked(key *replicaCommon.EnvelopeKey) {
	if use := k.leases[key]; use != nil {
		use.retired = true
		return
	}
	key.PrivateKey.Reset()
}

func (l *envelopeKeyLease) Release() {
	l.once.Do(func() {
		k := l.owner
		k.keysLock.Lock()
		defer k.keysLock.Unlock()
		use := k.leases[l.EnvelopeKey]
		use.users--
		if use.users == 0 {
			if use.retired {
				l.PrivateKey.Reset()
			}
			delete(k.leases, l.EnvelopeKey)
		}
	})
}
