// SPDX-License-Identifier: AGPL-3.0-only

//go:build !go1.27

package common

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMLDSA65NeedsGo127(t *testing.T) {
	opts := &Options{Signature: SignatureMLDSA65}
	require.ErrorContains(t, opts.Validate(), "Go 1.27")
	_, err := NewEpochKeys(t.TempDir(), CurrentEpoch, opts)
	require.Error(t, err)
	path := filepath.Join(t.TempDir(), "quic-tls.key")
	_, err = LoadStaticKey(path, opts)
	require.Error(t, err)
	require.NoFileExists(t, path)
}
