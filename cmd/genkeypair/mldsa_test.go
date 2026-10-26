// SPDX-License-Identifier: AGPL-3.0-only

//go:build go1.27

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/quic/common"
)

func TestGenkeypairWritesAnMLDSA65QUICKey(t *testing.T) {
	out := filepath.Join(t.TempDir(), "gateway1")
	require.NoError(t, runGenkeypairArgs("--type", "quic", "--scheme", common.SignatureMLDSA65, "--out", out))
	pin, err := os.ReadFile(out + ".quic-tls.hash")
	require.NoError(t, err)
	key, err := common.ReadStaticKey(out+".quic-tls.key", &common.Options{Signature: common.SignatureMLDSA65})
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(key.Hash())+"\n", string(pin))
	ed, err := common.ReadStaticKey(out+".quic-tls.key", nil)
	require.NoError(t, err)
	require.NotEqual(t, ed.Hash(), key.Hash())
}
