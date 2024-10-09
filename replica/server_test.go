// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/replica/config"
)

func TestServerFilePersistence(t *testing.T) {
	dname, err := os.MkdirTemp("", fmt.Sprintf("replca.testState %d", os.Getpid()))
	require.NoError(t, err)
	defer os.RemoveAll(dname)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 1234
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	require.NotNil(t, geo)

	cfg := &config.Config{
		PKI:        &config.PKI{},
		Identifier: "replica1",
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		DataDir:            dname,
		SphinxGeometry:     geo,
		PKISignatureScheme: "ed25519",
		ReplicaNIKEScheme:  "x25519",
		WireKEMScheme:      "x25519",
		Addresses:          []string{"tcp://127.0.0.1:34394"},
	}

	err = cfg.FixupAndValidate(true)
	require.NoError(t, err)

	server1, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server1.linkKey)
	require.NotNil(t, server1.identityPrivateKey)
	server1.Shutdown()

	server2, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server2.linkKey)
	require.NotNil(t, server2.identityPrivateKey)
	server2.Shutdown()

	require.Equal(t, server1.replicaPrivateKey, server2.replicaPrivateKey)
	require.Equal(t, server1.replicaPublicKey.Bytes(), server2.replicaPublicKey.Bytes())
	require.Equal(t, server1.identityPrivateKey, server2.identityPrivateKey)
	require.Equal(t, server1.identityPublicKey, server2.identityPublicKey)

	require.NotNil(t, server1.linkKey)
	require.NotNil(t, server2.linkKey)

	linkblob1, err := server1.linkKey.MarshalBinary()
	require.NoError(t, err)

	linkblob2, err := server2.linkKey.MarshalBinary()
	require.NoError(t, err)

	require.Equal(t, linkblob1, linkblob2)
}
