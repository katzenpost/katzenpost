// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server/config"
)

func TestParamsGenHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_PARAMS_GEN_HELPER") != "1" {
		return
	}
	logBackend, tmpDir := newParamsHelperLog("kaetzchen_params_gen_helper")
	socketFile, fromHost := cborplugin.HostSocketPath(filepath.Join(tmpDir, "helper.socket"))
	if !fromHost {
		os.Exit(3)
	}
	params := map[string]interface{}{"gen": os.Getenv("GO_PARAMS_GEN")}
	srv := cborplugin.NewServer(logBackend.GetLogger("helper"), socketFile, &cborplugin.RequestFactory{}, &paramsPlugin{params: params})
	srv.Accept()
	srv.Wait()
	os.Exit(0)
}

func TestCBORPluginParametersEndWithThePlugin(t *testing.T) {
	t.Setenv("GO_WANT_PARAMS_GEN_HELPER", "1")
	t.Setenv("GO_PARAMS_GEN", "1")
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
		Config:         map[string]interface{}{"test.run": "TestParamsGenHelperProcess"},
		Command:        os.Args[0],
		MaxConcurrency: 1,
	}}
	w, err := NewCBORPluginWorker(goo)
	require.NoError(t, err)
	t.Cleanup(w.Halt)

	var ep [constants.RecipientIDLength]byte
	copy(ep[:], "params")
	gen := func() interface{} { return w.AdvertisedData()["params"]["gen"] }
	require.Eventually(t, func() bool { return gen() == "1" }, 10*time.Second, 50*time.Millisecond)

	require.NoError(t, w.UnregisterKaetzchen("params"))
	require.Eventually(t, func() bool { return !w.IsKaetzchen(ep) }, 10*time.Second, 50*time.Millisecond)
	require.NotContains(t, w.AdvertisedData(), "params", "a stopped plugin's parameters are still advertised")

	t.Setenv("GO_PARAMS_GEN", "2")
	require.NoError(t, w.RegisterKaetzchen("params"))
	require.Eventually(t, func() bool { return gen() == "2" }, 10*time.Second, 50*time.Millisecond, "a restarted plugin's parameters are ignored")
}
