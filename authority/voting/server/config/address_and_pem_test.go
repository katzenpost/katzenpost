// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func testGeometry() *geo.Geometry {
	return geo.GeometryFromUserForwardPayloadLength(nikeschemes.ByName("x25519"), 2000, true, 5)
}

func TestServerValidateDefaultsTheAddress(t *testing.T) {
	s := &Server{WireKEMScheme: "x25519", PKISignatureScheme: "ed25519", DataDir: t.TempDir()}
	err := s.validate()
	if err != nil && strings.Contains(err.Error(), "no globally routable") {
		t.Skipf("no routable IPv4 address on this host: %v", err)
	}
	require.NoError(t, err)
	require.Len(t, s.Addresses, 1)
	require.True(t, strings.HasSuffix(s.Addresses[0], defaultAddress))
}

func TestFixupAndValidateRejectsAnUnreadableIdentityPEM(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "identity.public.pem"), 0o700))
	cfg := &Config{Server: &Server{WireKEMScheme: "x25519", PKISignatureScheme: "ed25519", DataDir: dir, Addresses: []string{"tcp://127.0.0.1:1"}}}
	cfg.SphinxGeometry = testGeometry()
	err := cfg.FixupAndValidate(false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "is a directory")
}
