package client

import (
	"io"
	"testing"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/require"
)

func TestNewCapFromSeed(t *testing.T) {
	require := require.New(t)
	ctx := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, ctx)
	require.NoError(err)
	edPrivKey, edPubKey, err := ed25519.NewKeypair(rand.Reader)
	require.NoError(err)
	ownerCap := NewOwnerCapFromSeed(edPrivKey, ctx)
	readCapBytesByOwner, err := ownerCap.UniversalReadCap().MarshalBinary()
	require.NoError(err)
	readCap := NewUniversalReadCapFromSeed(edPubKey, ctx)
	readCapBytes, err := readCap.MarshalBinary()
	require.NoError(err)
	require.Equal(readCapBytes, readCapBytesByOwner)
}
