// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	signpem "github.com/katzenpost/hpqc/sign/pem"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/quic/common"
	"github.com/katzenpost/katzenpost/replica/config"
)

const (
	quicRestartChildAddr = "KATZENPOST_QUIC_RESTART_CHILD_ADDR"
	quicRestartChildKey  = "KATZENPOST_QUIC_RESTART_CHILD_KEY"
	quicRestartScheme    = "Ed25519 Sphincs+"
)

func runQuicRestartChild(t *testing.T, addr string) {
	identityPrivateKey, err := signpem.FromPrivatePEMFile(os.Getenv(quicRestartChildKey), signschemes.ByName(quicRestartScheme))
	require.NoError(t, err)
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	server := &Server{cfg: &config.Config{}, logBackend: backend, identityPrivateKey: identityPrivateKey}
	_, err = newListener(server, 0, "quic://"+addr)
	require.NoError(t, err)
	fmt.Println("listening")
	time.Sleep(time.Minute)
}

func startQuicRestartChild(t *testing.T, addr, identityPrivateKeyFile string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestQuicListenerRestartResetsOldConnections$")
	cmd.Env = append(os.Environ(), quicRestartChildAddr+"="+addr, quicRestartChildKey+"="+identityPrivateKeyFile)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "listening" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		require.True(t, ok, "the listener child exited before listening")
	case <-time.After(30 * time.Second):
		t.Fatal("the listener child did not start")
	}
	return cmd
}

func TestQuicListenerRestartResetsOldConnections(t *testing.T) {
	if addr := os.Getenv(quicRestartChildAddr); addr != "" {
		runQuicRestartChild(t, addr)
		return
	}
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := probe.LocalAddr().String()
	require.NoError(t, probe.Close())

	_, identityPrivateKey, err := signschemes.ByName(quicRestartScheme).GenerateKey()
	require.NoError(t, err)
	identityPrivateKeyFile := filepath.Join(t.TempDir(), "identity.private.pem")
	require.NoError(t, signpem.PrivateKeyToFile(identityPrivateKeyFile, identityPrivateKey))

	first := startQuicRestartChild(t, addr, identityPrivateKeyFile)
	u, err := url.Parse("quic://" + addr)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := common.DialURL(u, ctx, nil)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, first.Process.Kill())
	first.Wait()
	startQuicRestartChild(t, addr, identityPrivateKeyFile)

	restarted := time.Now()
	_, err = conn.Write(make([]byte, 512))
	require.NoError(t, err)
	qc := conn.(*common.QuicConn)
	select {
	case <-qc.Conn.Context().Done():
		cause := context.Cause(qc.Conn.Context())
		var reset *quic.StatelessResetError
		require.True(t, errors.As(cause, &reset), "the old connection closed with %v, not a stateless reset", cause)
		t.Logf("old connection closed %v after the restart: %v", time.Since(restarted), cause)
	case <-time.After(15 * time.Second):
		t.Fatalf("the connection to the old listener was still open %v after the restart", time.Since(restarted))
	}
}
