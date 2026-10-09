// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestNoticeSectionLoads(t *testing.T) {
	cfg := new(Config)
	require.NoError(t, toml.Unmarshal([]byte("[Notice]\nMinClientVersion = \"v0.0.105\"\nClientNotice = \"hello\"\n"), cfg))
	require.Equal(t, "v0.0.105", cfg.Notice.MinClientVersion)
	require.Equal(t, "hello", cfg.Notice.ClientNotice)
}

func TestNoticeValidate(t *testing.T) {
	require.NoError(t, (&Notice{}).validate())
	require.NoError(t, (&Notice{MinClientVersion: "v1", ClientNotice: "hi"}).validate())
	require.Error(t, (&Notice{MinClientVersion: strings.Repeat("v", 33)}).validate())
	require.Error(t, (&Notice{ClientNotice: "bad\x00"}).validate())
}

func TestFixupAndValidateRejectsBadNotice(t *testing.T) {
	f := newFixture(t)
	f.cfg.Notice = Notice{MinClientVersion: "v0.0.105", ClientNotice: "hello"}
	require.NoError(t, f.cfg.FixupAndValidate(false))
	f.cfg.Notice.ClientNotice = strings.Repeat("n", 513)
	require.Error(t, f.cfg.FixupAndValidate(false))
}
