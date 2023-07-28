package client2

import (
	"testing"

	"github.com/katzenpost/katzenpost/client2/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/stretchr/testify/require"
)

func TestDockerClientSendReceive(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	egressSize := 100
	d, err := NewDaemon(cfg, egressSize)
	require.NoError(t, err)
	err = d.Start()
	require.NoError(t, err)

	thin := NewThinClient()

	err = thin.Dial()
	require.NoError(t, err)
	require.Nil(t, err)

	doc := thin.PKIDocument()
	require.NotNil(t, doc)

	pingTargets := []*cpki.MixDescriptor{}
	for i := 0; i < len(doc.Providers); i++ {
		_, ok := doc.Providers[i].Kaetzchen["echo"]
		if ok {
			pingTargets = append(pingTargets, doc.Providers[i])
		}
	}
	message := []byte("hello alice, this is bob.")
	nodeIdKey := pingTargets[0].IdentityKey.Sum256()
	thin.SendMessage(message, &nodeIdKey, []byte("echo"))

	d.Halt()
}
