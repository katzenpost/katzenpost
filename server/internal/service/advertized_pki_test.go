// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/sign"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/connlimit"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/service/kaetzchen"
)

type advertGlue struct {
	cfg *config.Config
	log *log.Backend
}

func (g *advertGlue) Config() *config.Config            { return g.cfg }
func (g *advertGlue) LogBackend() *log.Backend          { return g.log }
func (g *advertGlue) IdentityKey() sign.PrivateKey      { return nil }
func (g *advertGlue) IdentityPublicKey() sign.PublicKey { return nil }
func (g *advertGlue) LinkKey() kem.PrivateKey           { return nil }
func (g *advertGlue) Management() *thwack.Server        { return nil }
func (g *advertGlue) MixKeys() glue.MixKeys             { return nil }
func (g *advertGlue) PKI() glue.PKI                     { return nil }
func (g *advertGlue) Gateway() glue.Gateway             { return nil }
func (g *advertGlue) ServiceNode() glue.ServiceNode     { return nil }
func (g *advertGlue) Scheduler() glue.Scheduler         { return nil }
func (g *advertGlue) Connector() glue.Connector         { return nil }
func (g *advertGlue) Listeners() []glue.Listener        { return nil }
func (g *advertGlue) Decoy() glue.Decoy                 { return nil }
func (g *advertGlue) PeerConnSet() *connlimit.PeerSet   { return nil }
func (g *advertGlue) ReshadowCryptoWorkers()            {}

type advertPlugin struct {
	server *cborplugin.Server
}

func (p *advertPlugin) RegisterConsumer(s *cborplugin.Server) { p.server = s }

func (p *advertPlugin) OnCommand(cmd cborplugin.Command) error {
	if req, ok := cmd.(*cborplugin.Request); ok && req.IsParametersRequest {
		p.server.Write(cborplugin.NewParametersResponse(map[string]interface{}{"k": "v", "clash": "plugin"}))
	}
	return nil
}

func TestAdvertHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_ADVERT_HELPER") != "1" {
		return
	}
	tmpDir, err := os.MkdirTemp("", "service_advert_helper")
	if err != nil {
		os.Exit(1)
	}
	logBackend, err := log.New(filepath.Join(tmpDir, "helper.log"), "DEBUG", false)
	if err != nil {
		os.Exit(1)
	}
	socketFile, fromHost := cborplugin.HostSocketPath(filepath.Join(tmpDir, "helper.socket"))
	if !fromHost {
		os.Exit(3)
	}
	srv := cborplugin.NewServer(logBackend.GetLogger("helper"), socketFile, &cborplugin.RequestFactory{}, &advertPlugin{})
	srv.Accept()
	srv.Wait()
	os.Exit(0)
}

func TestKaetzchenForPKIMergesPluginAndConfigData(t *testing.T) {
	t.Setenv("GO_WANT_ADVERT_HELPER", "1")
	logFile := filepath.Join(t.TempDir(), "service.log")
	backend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	g := &advertGlue{
		log: backend,
		cfg: &config.Config{
			Server:         &config.Server{IsServiceNode: true},
			Logging:        &config.Logging{},
			PKI:            &config.PKI{},
			Debug:          &config.Debug{},
			SphinxGeometry: geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5),
			ServiceNode: &config.ServiceNode{
				CBORPluginKaetzchen: []*config.CBORPluginKaetzchen{
					{
						Capability:        "params",
						Endpoint:          "params",
						Config:            map[string]interface{}{"test.run": "TestAdvertHelperProcess"},
						Command:           os.Args[0],
						MaxConcurrency:    1,
						PKIAdvertizedData: map[string]map[string]interface{}{"params": {"clash": "config", "s": "static"}},
					},
					{
						Capability:        "off",
						Endpoint:          "off",
						Disable:           true,
						PKIAdvertizedData: map[string]map[string]interface{}{"other": {"x": "y"}},
					},
				},
			},
		},
	}
	w, err := kaetzchen.NewCBORPluginWorker(g)
	require.NoError(t, err)
	t.Cleanup(w.Halt)
	p := &serviceNode{
		glue:                      g,
		log:                       backend.GetLogger("service"),
		kaetzchenWorker:           &kaetzchen.KaetzchenWorker{},
		cborPluginKaetzchenWorker: w,
	}

	want := map[string]map[string]interface{}{"params": {"k": "v", "clash": "config", "s": "static"}}
	require.Eventually(t, func() bool {
		got, plugins, err := p.KaetzchenForPKI()
		return err == nil && reflect.DeepEqual(want, got) && plugins["params"] != nil
	}, 10*time.Second, 50*time.Millisecond)

	blob, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.True(t, strings.Contains(string(blob), `config overrides plugin parameter "clash"`), "clash not logged")
}
