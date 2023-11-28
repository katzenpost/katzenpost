package client2

import (
	"testing"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/stretchr/testify/require"
)

func NoTestDaemonStartStop(t *testing.T) {

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	d, err := NewDaemon(cfg, 123)
	require.NoError(t, err)

	err = d.Start()
	require.NoError(t, err)

	d.Halt()
}
