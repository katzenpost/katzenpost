// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func loadWithMetadata(t *testing.T, lines string) (*Config, error) {
	b, err := os.ReadFile("testdata/replica.toml")
	require.NoError(t, err)
	s := strings.Replace(string(b), "Identifier = \"replica1\"\n", "Identifier = \"replica1\"\n"+lines, 1)
	return Load([]byte(s), false)
}

func TestDescriptorMetadataConfig(t *testing.T) {
	cfg, err := loadWithMetadata(t, "")
	require.NoError(t, err)
	require.Empty(t, cfg.ContactInfo)
	require.Empty(t, cfg.SoftwareVersion)

	for contact, version := range map[string]string{
		"ops@example.org":        "auto",
		strings.Repeat("c", 256): strings.Repeat("v", 128),
	} {
		cfg, err := loadWithMetadata(t, "ContactInfo = \""+contact+"\"\nSoftwareVersion = \""+version+"\"\n")
		require.NoError(t, err)
		require.Equal(t, contact, cfg.ContactInfo)
		require.Equal(t, version, cfg.SoftwareVersion)
	}
}

func TestDescriptorMetadataConfigRejectsMalformed(t *testing.T) {
	for _, line := range []string{
		"ContactInfo = \"ops\\u0001\"",
		"ContactInfo = \"" + strings.Repeat("c", 257) + "\"",
		"SoftwareVersion = \"v1\\u007f\"",
		"SoftwareVersion = \"" + strings.Repeat("v", 129) + "\"",
	} {
		_, err := loadWithMetadata(t, line+"\n")
		require.ErrorContains(t, err, strings.Fields(line)[0], line)
	}
}
