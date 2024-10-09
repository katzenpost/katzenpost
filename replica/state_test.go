// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/config"
)

func TestState(t *testing.T) {
	dname, err := os.MkdirTemp("", "replca.testState")
	require.NoError(t, err)
	//defer os.RemoveAll(dname)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 1234
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	require.NotNil(t, geo)

	cfg := &config.Config{
		DataDir:        dname,
		SphinxGeometry: geo,
	}

	s := &Server{
		cfg: cfg,
	}

	st := &state{
		server: s,
	}

	st.initDB()

	cmds := commands.NewStorageReplicaCommands(geo)
	require.NotNil(t, cmds)

	replicaWriteCmd1 := &commands.ReplicaWrite{
		Cmds:      cmds,
		ID:        &[32]byte{},
		Signature: &[32]byte{},
		Payload:   []byte("hello i am a payload"),
	}
	_, err = rand.Reader.Read(replicaWriteCmd1.ID[:])
	require.NoError(t, err)

	_, err = rand.Reader.Read(replicaWriteCmd1.Signature[:])
	require.NoError(t, err)

	err = st.handleReplicaWrite(replicaWriteCmd1)
	require.NoError(t, err)

	replicaReadCmd := &commands.ReplicaRead{
		Cmds: cmds,
		ID:   &[32]byte{},
	}
	copy(replicaReadCmd.ID[:], replicaWriteCmd1.ID[:])

	replicaWriteCmd2, err := st.handleReplicaRead(replicaReadCmd)
	require.NoError(t, err)

	require.Equal(t, replicaWriteCmd1.ID[:], replicaWriteCmd2.ID[:])
	require.Equal(t, replicaWriteCmd1.Signature[:], replicaWriteCmd2.Signature[:])
	require.Equal(t, replicaWriteCmd1.Payload, replicaWriteCmd2.Payload[:len(replicaWriteCmd1.Payload)])
}
