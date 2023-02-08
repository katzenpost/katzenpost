package common 

import (
	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"

)
func TestCreateRWCap(t *testing.T) {
	require := require.New(t)
	// create a capability key
	pk, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err)

	rwCap := NewRWCap(pk)
	addr := []byte("we can use whatever byte sequence we like as address here")
	id := rwCap.Addr(addr)
	wKey := rwCap.Write(addr)
	require.Equal(wKey.PublicKey().Bytes(), id.WritePk().Bytes())

	rKey := rwCap.Read(addr)
	require.Equal(rKey.PublicKey().Bytes(), id.ReadPk().Bytes())
}
