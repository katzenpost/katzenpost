// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func openSchemaTestDB(t *testing.T, seed map[string][]byte) *state {
	t.Helper()
	st, _, _ := newSingleAuthorityState(t)
	db, err := bolt.Open(filepath.Join(t.TempDir(), "persistence.db"), 0600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	if seed != nil {
		require.NoError(t, db.Update(func(tx *bolt.Tx) error {
			bkt, err := tx.CreateBucketIfNotExists([]byte("metadata"))
			if err != nil {
				return err
			}
			for k, v := range seed {
				if err := bkt.Put([]byte(k), v); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	st.db = db
	return st
}

func storedSchema(t *testing.T, st *state) []byte {
	t.Helper()
	var v []byte
	require.NoError(t, st.db.View(func(tx *bolt.Tx) error {
		v = append([]byte(nil), tx.Bucket([]byte("metadata")).Get([]byte("schema"))...)
		return nil
	}))
	return v
}

func TestPersistenceSchemaFresh(t *testing.T) {
	st := openSchemaTestDB(t, nil)
	require.NoError(t, st.restorePersistence())
	require.Equal(t, []byte{1}, storedSchema(t, st))
	require.NoError(t, st.restorePersistence())
}

func TestPersistenceSchemaLegacy(t *testing.T) {
	st := openSchemaTestDB(t, map[string][]byte{"version": []byte("v0.0.70")})
	require.NoError(t, st.restorePersistence())
	require.Equal(t, []byte{1}, storedSchema(t, st))
}

func TestPersistenceSchemaMismatch(t *testing.T) {
	for _, v := range [][]byte{{0}, {2}, {0xff}, {}, {1, 0}} {
		st := openSchemaTestDB(t, map[string][]byte{"version": []byte("v0.0.70"), "schema": v})
		require.Error(t, st.restorePersistence(), "schema %x", v)
	}
}
