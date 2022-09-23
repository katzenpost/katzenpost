// kaetzchen_test.go - Tests for the KaetzchenWorker
// Copyright (C) 2018  David Stainton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package kaetzchen

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/monotime"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
	"github.com/katzenpost/katzenpost/server/spool"
	"github.com/katzenpost/katzenpost/server/userdb"
)

type mockUserDB struct {
	provider *mockProvider
}

func (u *mockUserDB) Exists([]byte) bool {
	return true
}

func (u *mockUserDB) IsValid([]byte, wire.PublicKey) bool { return true }

func (u *mockUserDB) Add([]byte, wire.PublicKey, bool) error { return nil }

func (u *mockUserDB) SetIdentity([]byte, wire.PublicKey) error { return nil }

func (u *mockUserDB) Link([]byte) (wire.PublicKey, error) {
	return nil, nil
}

func (u *mockUserDB) Identity([]byte) (wire.PublicKey, error) {
	return u.provider.userKey, nil
}

func (u *mockUserDB) Remove([]byte) error { return nil }

func (u *mockUserDB) Close() {}

type mockSpool struct{}

func (s *mockSpool) StoreMessage(u, msg []byte) error { return nil }

func (s *mockSpool) StoreSURBReply(u []byte, id *[constants.SURBIDLength]byte, msg []byte) error {
	return nil
}

func (s *mockSpool) Get(u []byte, advance bool) (msg, surbID []byte, remaining int, err error) {
	return []byte{1, 2, 3}, nil, 1, nil
}

func (s *mockSpool) Remove(u []byte) error { return nil }

func (s *mockSpool) VacuumExpired(udb userdb.UserDB, ignoreIdentities map[[32]byte]interface{}) error {
	return nil
}

func (s *mockSpool) Vacuum(udb userdb.UserDB) error { return nil }

func (s *mockSpool) Close() {}

type mockProvider struct {
	userName string
	userKey  wire.PublicKey
}

func (p *mockProvider) Halt() {}

func (p *mockProvider) UserDB() userdb.UserDB {
	return &mockUserDB{
		provider: p,
	}
}

func (p *mockProvider) Spool() spool.Spool {
	return &mockSpool{}
}

func (p *mockProvider) AuthenticateClient(*wire.PeerCredentials) bool {
	return true
}

func (p *mockProvider) OnPacket(*packet.Packet) {}

func (p *mockProvider) KaetzchenForPKI() (map[string]map[string]interface{}, error) {
	return nil, nil
}

type mockDecoy struct{}

func (d *mockDecoy) Halt() {}

func (d *mockDecoy) OnNewDocument(*pkicache.Entry) {}

func (d *mockDecoy) OnPacket(*packet.Packet) {}

type mockServer struct {
	cfg               *config.Config
	logBackend        *log.Backend
	identityKey       sign.PrivateKey
	identityPublicKey sign.PublicKey
	linkKey           wire.PrivateKey
	management        *thwack.Server
	mixKeys           glue.MixKeys
	pki               glue.PKI
	provider          glue.Provider
	scheduler         glue.Scheduler
	connector         glue.Connector
	listeners         []glue.Listener
}

type mockGlue struct {
	s *mockServer
}

func (g *mockGlue) Config() *config.Config {
	return g.s.cfg
}

func (g *mockGlue) LogBackend() *log.Backend {
	return g.s.logBackend
}

func (g *mockGlue) IdentityKey() sign.PrivateKey {
	return g.s.identityKey
}

func (g *mockGlue) IdentityPublicKey() sign.PublicKey {
	return g.s.identityPublicKey
}

func (g *mockGlue) LinkKey() wire.PrivateKey {
	return g.s.linkKey
}

func (g *mockGlue) Management() *thwack.Server {
	return g.s.management
}

func (g *mockGlue) MixKeys() glue.MixKeys {
	return g.s.mixKeys
}

func (g *mockGlue) PKI() glue.PKI {
	return g.s.pki
}

func (g *mockGlue) Provider() glue.Provider {
	return g.s.provider
}

func (g *mockGlue) Scheduler() glue.Scheduler {
	return g.s.scheduler
}

func (g *mockGlue) Connector() glue.Connector {
	return g.s.connector
}

func (g *mockGlue) Listeners() []glue.Listener {
	return g.s.listeners
}

func (g *mockGlue) ReshadowCryptoWorkers() {}

func (g *mockGlue) Decoy() glue.Decoy {
	return &mockDecoy{}
}

type MockKaetzchen struct {
	capability string
	parameters Parameters
	receivedCh chan bool
}

func (m *MockKaetzchen) Capability() string {
	return m.capability
}

func (m *MockKaetzchen) Parameters() Parameters {
	return m.parameters
}

func (m *MockKaetzchen) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	m.receivedCh <- true
	return nil, nil
}

func (m *MockKaetzchen) Halt() {}

func TestKaetzchenWorker(t *testing.T) {

	datadir := os.TempDir()

	idKey, idPubKey := cert.Scheme.NewKeypair()
	err := pem.ToFile(filepath.Join(datadir, "identity.private.pem"), idKey)
	require.NoError(t, err)

	err = pem.ToFile(filepath.Join(datadir, "identity.public.pem"), idPubKey)
	require.NoError(t, err)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	scheme := wire.NewScheme()
	userKey := scheme.GenerateKeypair(rand.Reader)
	linkKey := scheme.GenerateKeypair(rand.Reader)

	mockProvider := &mockProvider{
		userName: "alice",
		userKey:  userKey.PublicKey(),
	}

	goo := &mockGlue{
		s: &mockServer{
			logBackend: logBackend,
			provider:   mockProvider,
			linkKey:    linkKey,
			cfg: &config.Config{
				Server:  &config.Server{},
				Logging: &config.Logging{},
				Provider: &config.Provider{
					Kaetzchen: []*config.Kaetzchen{
						&config.Kaetzchen{
							Capability: "echo",
							Endpoint:   "echo",
							Config:     map[string]interface{}{},
							Disable:    false,
						},
					},
				},
				PKI:        &config.PKI{},
				Management: &config.Management{},
				Debug: &config.Debug{
					NumKaetzchenWorkers: 3,
					KaetzchenDelay:      300,
				},
			},
		},
	}

	kaetzWorker, err := New(goo)
	require.NoError(t, err)

	params := make(Parameters)
	params[ParameterEndpoint] = "+test"
	mockService := &MockKaetzchen{
		capability: "test",
		parameters: params,
		receivedCh: make(chan bool),
	}

	kaetzWorker.registerKaetzchen(mockService)

	recipient := [sConstants.RecipientIDLength]byte{}
	copy(recipient[:], []byte("+test"))
	require.True(t, kaetzWorker.IsKaetzchen(recipient))

	pkiMap := kaetzWorker.KaetzchenForPKI()
	_, ok := pkiMap["test"]
	require.True(t, ok)

	geo := sphinx.DefaultGeometry()

	// invalid packet test case
	payload := make([]byte, geo.PacketLength)
	testPacket, err := packet.New(payload)
	require.NoError(t, err)
	testPacket.Recipient = &commands.Recipient{
		ID: recipient,
	}
	testPacket.DispatchAt = monotime.Now()

	testPacket.Payload = make([]byte, geo.ForwardPayloadLength-1) // off by one erroneous size
	kaetzWorker.OnKaetzchen(testPacket)

	// timeout test case
	payload = make([]byte, geo.PacketLength)
	testPacket, err = packet.New(payload)
	require.NoError(t, err)
	testPacket.Recipient = &commands.Recipient{
		ID: recipient,
	}
	testPacket.DispatchAt = monotime.Now() - time.Duration(goo.Config().Debug.KaetzchenDelay)*time.Millisecond
	testPacket.Payload = make([]byte, geo.ForwardPayloadLength)
	kaetzWorker.OnKaetzchen(testPacket)

	// working test case
	payload = make([]byte, geo.PacketLength)
	testPacket, err = packet.New(payload)
	require.NoError(t, err)
	testPacket.Recipient = &commands.Recipient{
		ID: recipient,
	}
	testPacket.DispatchAt = monotime.Now()
	testPacket.Payload = make([]byte, geo.ForwardPayloadLength)

	kaetzWorker.OnKaetzchen(testPacket)
	<-mockService.receivedCh

	// test that we dropped two packets from the timeout and
	// invalid packet test casses
	time.Sleep(time.Duration(goo.Config().Debug.KaetzchenDelay) * time.Millisecond)
	require.Equal(t, uint64(2), kaetzWorker.getDropCounter())

	kaetzWorker.Halt()
}
