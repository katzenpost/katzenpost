package client2

import (
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/stretchr/testify/require"
)

func TestDaemonStartStop(t *testing.T) {

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	egressSize := 100
	d, err := NewDaemon(cfg, egressSize)
	require.NoError(t, err)

	err = d.Start()
	require.NoError(t, err)

	time.Sleep(time.Second * 3)

	d.Shutdown()
}
