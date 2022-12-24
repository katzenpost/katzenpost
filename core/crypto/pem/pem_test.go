// pem_test.go - PEM tests
//
// Copyright (C) 2022  David Stainton.
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

package pem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
)

func TestToFromPEM(t *testing.T) {

	datadir := os.TempDir()

	idKey, _ := cert.Scheme.NewKeypair()
	err := ToFile(filepath.Join(datadir, "identity.private.pem"), idKey)
	require.NoError(t, err)

}

func TestToFromPEM(t *testing.T) {
	verifyKeyString1 := `-----BEGIN ED25519 SPHINCS+ PUBLIC KEY-----
3zXGXWKZeW7cgLRKZPeF73Yi0+J+BtEzfoHM1SXMqdB30p0iAy1JDzaLWPOdAJNq
jWmeAbCVBJkDkRtdzghri6me5ZgEwQ3tr/OVK2Podxl3dIKP+riONi3po+D57ryg
-----END ED25519 SPHINCS+ PUBLIC KEY-----
`
	_, pubKey := Scheme.NewKeypair()

	err := pem.FromPEMString(verifyKeyString1, pubKey)
	require.NoError(t, err)

	verifyKeyString2 := string(pem.ToPEMBytes(pubKey))
	require.Equal(t, verifyKeyString1, verifyKeyString2)
}

func TestExistsAndNotExists(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "TestBothExists")
	require.NoError(t, err)

	privKey, pubKey := cert.Scheme.NewKeypair()

	pubPem := filepath.Join(tmpdir, "pub.pem")
	privPem := filepath.Join(tmpdir, "priv.pem")

	err = ToFile(pubPem, pubKey)
	require.NoError(t, err)

	err = ToFile(privPem, privKey)
	require.NoError(t, err)

	require.True(t, Exists(pubPem))
	require.True(t, Exists(privPem))

	require.True(t, BothExists(pubPem, privPem))

	require.False(t, BothExists(pubPem, privPem+"lala"))
	require.False(t, BothExists(pubPem+"lala", privPem))

	require.False(t, Exists(pubPem+"lala"))
	require.False(t, Exists(privPem+"lala"))

	require.True(t, BothNotExists(pubPem+"lala", privPem+"lala"))
	require.False(t, BothNotExists(pubPem+"lala", privPem))
}
