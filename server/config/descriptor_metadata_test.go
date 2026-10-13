// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDescriptorMetadataConfig(t *testing.T) {
	cfg, err := Load([]byte(serverTOML(t, "")))
	require.NoError(t, err)
	require.Empty(t, cfg.Server.ContactInfo)
	require.Empty(t, cfg.Server.SoftwareVersion)

	for contact, version := range map[string]string{
		"ops@example.org":        "auto",
		strings.Repeat("c", 256): strings.Repeat("v", 128),
	} {
		cfg, err := Load([]byte(serverTOML(t, "  ContactInfo = \""+contact+"\"\n  SoftwareVersion = \""+version+"\"\n")))
		require.NoError(t, err)
		require.Equal(t, contact, cfg.Server.ContactInfo)
		require.Equal(t, version, cfg.Server.SoftwareVersion)
	}
}

func TestDescriptorMetadataConfigRejectsMalformed(t *testing.T) {
	for _, line := range []string{
		"ContactInfo = \"ops\\u0001\"",
		"ContactInfo = \"" + strings.Repeat("c", 257) + "\"",
		"SoftwareVersion = \"v1\\u007f\"",
		"SoftwareVersion = \"" + strings.Repeat("v", 129) + "\"",
	} {
		_, err := Load([]byte(serverTOML(t, "  "+line+"\n")))
		require.ErrorContains(t, err, strings.Fields(line)[0], line)
	}
}
