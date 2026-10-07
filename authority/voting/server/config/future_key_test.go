// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadIgnoresUnknownFutureKeys(t *testing.T) {
	f := newFixture(t)
	_, err := Load([]byte("FutureKey = \"x\"\n"+f.tomlText()+"\n[FutureTable]\nFutureKey = 1\n"), false)
	require.NoError(t, err)
}
