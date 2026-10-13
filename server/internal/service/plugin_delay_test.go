// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server/config"
)

type delayEchoPlugin struct {
	server *cborplugin.Server
}

func (p *delayEchoPlugin) RegisterConsumer(s *cborplugin.Server) { p.server = s }

func (p *delayEchoPlugin) OnCommand(cmd cborplugin.Command) error {
	req, ok := cmd.(*cborplugin.Request)
	if !ok || req.IsParametersRequest {
		return nil
	}
	p.server.Write(&cborplugin.Response{
		RequestAt: req.RequestAt,
		Delay:     req.Delay,
		ID:        req.ID,
		Payload:   req.Payload,
		SURB:      req.SURB,
	})
	return nil
}

func TestDelayEchoHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_DELAY_ECHO_HELPER") != "1" {
		return
	}
	tmpDir, err := os.MkdirTemp("", "service_delay_echo_helper")
	if err != nil {
		os.Exit(1)
	}
	logBackend, err := log.New(filepath.Join(tmpDir, "helper.log"), "DEBUG", false)
	if err != nil {
		os.Exit(1)
	}
	socketFile, fromHost := cborplugin.HostSocketPath(filepath.Join(tmpDir, "helper.socket"))
	srv := cborplugin.NewServer(logBackend.GetLogger("helper"), socketFile, &cborplugin.RequestFactory{}, &delayEchoPlugin{})
	if !fromHost {
		fmt.Println(socketFile)
	}
	srv.Accept()
	srv.Wait()
	os.Exit(0)
}

func TestServiceNodeAppliesPluginDelayOnce(t *testing.T) {
	t.Setenv("GO_WANT_DELAY_ECHO_HELPER", "1")
	g := newServiceGlue(t, config.Debug{})
	g.cfg.ServiceNode.CBORPluginKaetzchen = []*config.CBORPluginKaetzchen{{
		Capability:     "delayecho",
		Endpoint:       "delayecho",
		Config:         map[string]interface{}{"test.run": "TestDelayEchoHelperProcess"},
		Command:        os.Args[0],
		MaxConcurrency: 1,
	}}
	n, err := New(g)
	require.NoError(t, err)
	sn := n.(*serviceNode)
	t.Cleanup(sn.Halt)
	var endpoint [constants.RecipientIDLength]byte
	copy(endpoint[:], "delayecho")
	require.Eventually(t, func() bool { return sn.cborPluginKaetzchenWorker.IsKaetzchen(endpoint) }, 10*time.Second, 10*time.Millisecond)

	const delay = 2 * time.Second
	pkt := echoRequest(t, g.cfg.SphinxGeometry, delay)
	pkt.Recipient.ID = endpoint
	recvAt := pkt.RecvAt
	sn.OnPacket(pkt)

	select {
	case r := <-g.sched.ch:
		held := r.at.Sub(recvAt)
		require.GreaterOrEqual(t, held, delay)
		require.LessOrEqual(t, held+r.pkt.Delay, delay+delay/4, "held %v then delayed the reply %v more", held, r.pkt.Delay)
	case <-time.After(10 * time.Second):
		t.Fatal("no plugin reply")
	}
}
