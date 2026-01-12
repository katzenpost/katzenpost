// state_persistence_test.go - Tests for persistence version handling.
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
	"path/filepath"
	"testing"

	"github.com/carlmjohnson/versioninfo"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestPersistenceVersionHandling(t *testing.T) {
	currentVersion := versioninfo.Short()

	tests := []struct {
		name           string
		storedVersion  []byte
		shouldMismatch bool
	}{
		{"legacy byte format", []byte{0}, true},
		{"old version string", []byte("v0.0.0-old"), true},
		{"current version", []byte(currentVersion), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "persistence.db")
			db, err := bolt.Open(dbPath, 0600, nil)
			require.NoError(t, err)

			err = db.Update(func(tx *bolt.Tx) error {
				bkt, _ := tx.CreateBucketIfNotExists([]byte("metadata"))
				return bkt.Put([]byte("version"), tt.storedVersion)
			})
			require.NoError(t, err)
			db.Close()

			db, err = bolt.Open(dbPath, 0600, nil)
			require.NoError(t, err)
			defer db.Close()

			var stored string
			db.View(func(tx *bolt.Tx) error {
				stored = string(tx.Bucket([]byte("metadata")).Get([]byte("version")))
				return nil
			})

			if tt.shouldMismatch {
				require.NotEqual(t, stored, currentVersion)
			} else {
				require.Equal(t, stored, currentVersion)
			}
		})
	}
}
