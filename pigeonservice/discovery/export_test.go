// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

// SetNow replaces the clock leases are judged by.
func (d *Directory) SetNow(now func() time.Time) { d.clock.Store(&now) }

// Republish purges forgotten entries and publishes a fresh snapshot.
func (d *Directory) Republish() { d.markDirty() }

// Entries counts the entries the directory remembers, live or not.
func (d *Directory) Entries() (n int) {
	d.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(descriptorsBucket).Stats().KeyN
		return nil
	})
	return n
}
