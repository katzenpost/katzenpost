package client2

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/charmbracelet/log"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	cfg := &Config{
		Net:       "tcp",
		Addr:      "localhost:6667",
		LogModule: "handler_",
		NewLoggerFn: func(prefix string) *log.Logger {
			logger := log.NewWithOptions(os.Stderr, log.Options{
				Prefix: prefix,
			})
			logger.SetLevel(log.DebugLevel)
			return logger
		},
	}

	s := NewServer(cfg)
	ctx, _ := context.WithCancel(context.Background())
	err := s.Start(ctx)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	conn, err := net.Dial(cfg.Net, cfg.Addr)
	require.NoError(t, err)

	conn2, err := net.Dial(cfg.Net, cfg.Addr)
	require.NoError(t, err)

	header := make([]byte, 4)
	message := []byte("hello")
	binary.BigEndian.PutUint32(header, uint32(len(message)))

	count, err := conn.Write(append(header[:4], message...))
	require.Equal(t, count, 4+len(message))
	require.NoError(t, err)

	count, err = conn2.Write(append(header[:4], message...))
	require.Equal(t, count, 4+len(message))
	require.NoError(t, err)

	s.Halt()
}
