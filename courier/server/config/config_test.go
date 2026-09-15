// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func newValidCourierConfig() *Config {
	return &Config{
		PKI:            &PKI{},
		WireKEMScheme:  "x25519",
		DataDir:        "/var/lib/courier",
		SphinxGeometry: &geo.Geometry{},
		Logging:        &Logging{Level: "INFO"},
	}
}

// The courier announces its plugin socket on stdout, so an unset
// Logging.File (which otherwise means "log to stdout") must fall back
// to a file rather than corrupt the handshake.
func TestFixupAndValidateDefaultsLogFile(t *testing.T) {
	cfg := newValidCourierConfig()
	require.NoError(t, cfg.FixupAndValidate())
	require.Equal(t, DefaultLogFile, cfg.Logging.File)
}

// A nil Logging block defaults to stdout via DefaultLogging; the same
// fallback must apply so the handshake stays clean.
func TestFixupAndValidateDefaultsLogFileWhenLoggingNil(t *testing.T) {
	cfg := newValidCourierConfig()
	cfg.Logging = nil
	require.NoError(t, cfg.FixupAndValidate())
	require.Equal(t, DefaultLogFile, cfg.Logging.File)
}

// An explicitly configured File must be preserved untouched.
func TestFixupAndValidatePreservesExplicitLogFile(t *testing.T) {
	cfg := newValidCourierConfig()
	cfg.Logging.File = "/var/log/katzenpost/courier.log"
	require.NoError(t, cfg.FixupAndValidate())
	require.Equal(t, "/var/log/katzenpost/courier.log", cfg.Logging.File)
}
