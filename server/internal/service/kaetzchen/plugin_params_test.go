// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server/config"
)

type paramsPlugin struct {
	server *cborplugin.Server
	params map[string]interface{}
}

func (p *paramsPlugin) RegisterConsumer(s *cborplugin.Server) { p.server = s }

func (p *paramsPlugin) OnCommand(cmd cborplugin.Command) error {
	if req, ok := cmd.(*cborplugin.Request); ok && req.IsParametersRequest {
		p.server.Write(cborplugin.NewParametersResponse(p.params))
	}
	return nil
}

func newParamsHelperLog(dirPrefix string) (*log.Backend, string) {
	tmpDir, err := os.MkdirTemp("", dirPrefix)
	if err != nil {
		os.Exit(1)
	}
	logBackend, err := log.New(filepath.Join(tmpDir, "helper.log"), "DEBUG", false)
	if err != nil {
		os.Exit(1)
	}
	return logBackend, tmpDir
}

func TestParamsHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_PARAMS_HELPER") != "1" {
		return
	}
	logBackend, tmpDir := newParamsHelperLog("kaetzchen_params_helper")
	own := filepath.Join(tmpDir, "helper.socket")
	socketFile, fromHost := cborplugin.HostSocketPath(own)
	if os.Getenv("GO_PARAMS_LEGACY") == "1" {
		socketFile, fromHost = own, false
	}
	params := map[string]interface{}{"k": "v", "clash": "plugin"}
	if os.Getenv("GO_PARAMS_HUGE") == "1" {
		params["huge"] = strings.Repeat("x", 8192)
	}
	srv := cborplugin.NewServer(logBackend.GetLogger("helper"), socketFile, &cborplugin.RequestFactory{}, &paramsPlugin{params: params})
	if !fromHost {
		fmt.Println(socketFile)
	}
	srv.Accept()
	srv.Wait()
	os.Exit(0)
}

func startParamsWorker(t *testing.T) *CBORPluginWorker {
	t.Helper()
	t.Setenv("GO_WANT_PARAMS_HELPER", "1")
	_, idKey, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	logBackend, err := log.New(filepath.Join(t.TempDir(), "worker.log"), "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { logBackend.Close() })
	_, userKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	_, linkKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	goo := getGlue(logBackend, &mockProvider{userName: "alice", userKey: userKey.Public()}, linkKey, idKey)
	goo.s.cfg.SphinxGeometry = geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5)
	goo.s.cfg.ServiceNode.CBORPluginKaetzchen = []*config.CBORPluginKaetzchen{{
		Capability:     "params",
		Endpoint:       "params",
		Config:         map[string]interface{}{"test.run": "TestParamsHelperProcess"},
		Command:        os.Args[0],
		MaxConcurrency: 1,
	}}
	w, err := NewCBORPluginWorker(goo)
	require.NoError(t, err)
	t.Cleanup(w.Halt)
	return w
}

func TestCBORPluginAdvertisesPluginParameters(t *testing.T) {
	w := startParamsWorker(t)
	require.Eventually(t, func() bool {
		return w.AdvertisedData()["params"]["k"] == "v"
	}, 10*time.Second, 50*time.Millisecond)
}

func TestCBORPluginRefusesHugeParameters(t *testing.T) {
	t.Setenv("GO_PARAMS_HUGE", "1")
	w := startParamsWorker(t)
	time.Sleep(time.Second)
	require.Empty(t, w.AdvertisedData()["params"])
}

func TestCBORPluginNeverAsksLegacyPluginForParameters(t *testing.T) {
	t.Setenv("GO_PARAMS_LEGACY", "1")
	w := startParamsWorker(t)
	time.Sleep(time.Second)
	require.Empty(t, w.AdvertisedData()["params"])
}
