// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type fixture struct {
	dir    string
	cfg    *Config
	idPub  sign.PublicKey
	idPEM  string
	lkPEM  string
	geoTOM string
}

func newFixture(t *testing.T) *fixture {
	dir := t.TempDir()
	ss := signschemes.ByName("ed25519")
	ks := kemschemes.ByName("x25519")
	idPub, _, err := ss.GenerateKey()
	require.NoError(t, err)
	require.NoError(t, signpem.PublicKeyToFile(filepath.Join(dir, "identity.public.pem"), idPub))
	lkPub, _, err := ks.GenerateKeyPair()
	require.NoError(t, err)
	node := func(name string) *Node {
		pub, _, err := ss.GenerateKey()
		require.NoError(t, err)
		require.NoError(t, signpem.PublicKeyToFile(filepath.Join(dir, name+".pem"), pub))
		return &Node{Identifier: name, IdentityPublicKeyPem: name + ".pem"}
	}
	rnode := func(name string, id uint8) *StorageReplicaNode {
		n := node(name)
		return &StorageReplicaNode{Identifier: n.Identifier, IdentityPublicKeyPem: n.IdentityPublicKeyPem, ReplicaID: id}
	}
	g := geo.GeometryFromUserForwardPayloadLength(nikeschemes.ByName("x25519"), 2000, true, 5)
	var buf bytes.Buffer
	require.NoError(t, toml.NewEncoder(&buf).Encode(map[string]interface{}{"SphinxGeometry": g}))
	cfg := &Config{
		Server: &Server{
			Identifier: "auth1", WireKEMScheme: "x25519", PKISignatureScheme: "ed25519",
			Addresses: []string{"tcp://127.0.0.1:30000"}, DataDir: dir,
		},
		Authorities: []*Authority{{
			Identifier: "auth1", IdentityPublicKey: idPub, PKISignatureScheme: "ed25519",
			LinkPublicKey: LinkPublicKey{PublicKey: lkPub}, WireKEMScheme: "x25519",
			Addresses: []string{"tcp://127.0.0.1:30000"},
		}},
		Mixes:           []*Node{node("mix1"), node("mix2")},
		GatewayNodes:    []*Node{node("gw1")},
		ServiceNodes:    []*Node{node("svc1")},
		StorageReplicas: []*StorageReplicaNode{rnode("rep1", 1)},
		SphinxGeometry:  g,
	}
	return &fixture{dir: dir, cfg: cfg, idPub: idPub, idPEM: signpem.ToPublicPEMString(idPub), lkPEM: kempem.ToPublicPEMString(lkPub), geoTOM: buf.String()}
}

func (f *fixture) tomlText() string {
	esc := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "\n", "\\n")
	}
	return `[Server]
Identifier = "auth1"
WireKEMScheme = "x25519"
PKISignatureScheme = "ed25519"
Addresses = ["tcp://127.0.0.1:30000"]
DataDir = "` + esc(f.dir) + `"

[[Authorities]]
Identifier = "auth1"
PKISignatureScheme = "ed25519"
WireKEMScheme = "x25519"
IdentityPublicKey = "` + esc(f.idPEM) + `"
LinkPublicKey = "` + esc(f.lkPEM) + `"
Addresses = ["tcp://127.0.0.1:30000"]

[Logging]
Level = "debug"

[Parameters]
Mu = 0.001

[Debug]
Layers = 2

[[Mixes]]
Identifier = "mix1"
IdentityPublicKeyPem = "mix1.pem"

[[Mixes]]
Identifier = "mix2"
IdentityPublicKeyPem = "mix2.pem"

[[GatewayNodes]]
Identifier = "gw1"
IdentityPublicKeyPem = "gw1.pem"

[[ServiceNodes]]
Identifier = "svc1"
IdentityPublicKeyPem = "svc1.pem"

[[StorageReplicas]]
Identifier = "rep1"
IdentityPublicKeyPem = "rep1.pem"
ReplicaID = 1

` + f.geoTOM
}

func TestFixupAndValidateAcceptsAndDefaults(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.cfg.FixupAndValidate(false))
	require.Equal(t, "NOTICE", f.cfg.Logging.Level)
	require.Equal(t, defaultMu, f.cfg.Parameters.Mu)
	require.Equal(t, defaultLayers, f.cfg.Debug.Layers)
	require.Equal(t, 30, f.cfg.Server.DialTimeoutSec)
	require.NoError(t, f.cfg.FixupAndValidate(true))
}

func TestValidateAuthoritiesWithFixture(t *testing.T) {
	f := newFixture(t)
	own := f.cfg.Authorities[0].LinkPublicKey.PublicKey
	require.NoError(t, f.cfg.ValidateAuthorities(own))
	other, _, err := kemschemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)
	require.Error(t, f.cfg.ValidateAuthorities(other))
	require.Error(t, (&Config{}).ValidateAuthorities(own))
	f.cfg.Authorities[0].LinkPublicKey = LinkPublicKey{}
	require.Error(t, f.cfg.ValidateAuthorities(own))
}

func TestLoadTOMLRoundTrip(t *testing.T) {
	f := newFixture(t)
	cfg, err := Load([]byte(f.tomlText()), false)
	require.NoError(t, err)
	require.Equal(t, "DEBUG", cfg.Logging.Level)
	require.Equal(t, 0.001, cfg.Parameters.Mu)
	require.Equal(t, 2, cfg.Debug.Layers)
	require.True(t, f.idPub.Equal(cfg.Authorities[0].IdentityPublicKey))
	txt, err := cfg.Authorities[0].LinkPublicKey.MarshalText()
	require.NoError(t, err)
	require.Equal(t, f.lkPEM, string(txt))
	path := filepath.Join(f.dir, "authority.toml")
	require.NoError(t, os.WriteFile(path, []byte(f.tomlText()), 0o600))
	cfg, err = LoadFile(path, true)
	require.NoError(t, err)
	require.True(t, cfg.Debug.GenerateOnly)
	_, err = LoadFile(filepath.Join(f.dir, "missing.toml"), false)
	require.Error(t, err)
	_, err = Load([]byte("= = ="), false)
	require.Error(t, err)
	_, err = Load([]byte("[Server]\nDataDir = \"/nonexistent\"\n"), false)
	require.Error(t, err)
}

func TestFixupAndValidateFillsBlankLogLevel(t *testing.T) {
	f := newFixture(t)
	f.cfg.Logging = &Logging{}
	require.NoError(t, f.cfg.FixupAndValidate(false))
	require.Equal(t, "NOTICE", f.cfg.Logging.Level)
}

func TestFixupAndValidateDetectsAddress(t *testing.T) {
	f := newFixture(t)
	f.cfg.Server.Addresses = nil
	if err := f.cfg.FixupAndValidate(false); err != nil {
		t.Skipf("no external IPv4 address available: %v", err)
	}
	require.Len(t, f.cfg.Server.Addresses, 1)
}

func TestAuthorityUnmarshalTOMLRejects(t *testing.T) {
	f := newFixture(t)
	base := map[string]interface{}{
		"PKISignatureScheme": "ed25519", "Identifier": "a", "IdentityPublicKey": f.idPEM,
		"LinkPublicKey": f.lkPEM, "WireKEMScheme": "x25519", "Addresses": []interface{}{"tcp://127.0.0.1:1"},
	}
	clone := func(mut func(m map[string]interface{})) map[string]interface{} {
		m := map[string]interface{}{}
		for k, v := range base {
			m[k] = v
		}
		mut(m)
		return m
	}
	a := new(Authority)
	require.NoError(t, a.UnmarshalTOML(clone(func(map[string]interface{}) {})))
	require.NoError(t, a.Validate())
	require.Error(t, a.UnmarshalTOML("nope"))
	cases := []func(m map[string]interface{}){
		func(m map[string]interface{}) { delete(m, "PKISignatureScheme") },
		func(m map[string]interface{}) { m["PKISignatureScheme"] = "nosuch" },
		func(m map[string]interface{}) { m["PKISignatureScheme"] = 1 },
		func(m map[string]interface{}) { delete(m, "Identifier") },
		func(m map[string]interface{}) { m["IdentityPublicKey"] = "garbage" },
		func(m map[string]interface{}) { delete(m, "LinkPublicKey") },
		func(m map[string]interface{}) { delete(m, "WireKEMScheme") },
		func(m map[string]interface{}) { m["WireKEMScheme"] = "nosuch" },
		func(m map[string]interface{}) { m["LinkPublicKey"] = "garbage" },
		func(m map[string]interface{}) { delete(m, "Addresses") },
	}
	for i, c := range cases {
		require.Error(t, new(Authority).UnmarshalTOML(clone(c)), "case %d", i)
	}
}

func TestAuthorityValidateRejects(t *testing.T) {
	f := newFixture(t)
	good := f.cfg.Authorities[0]
	mut := func(m func(a *Authority)) *Authority {
		a := *good
		m(&a)
		return &a
	}
	require.Error(t, mut(func(a *Authority) { a.WireKEMScheme = "" }).Validate())
	require.Error(t, mut(func(a *Authority) { a.WireKEMScheme = "nosuch" }).Validate())
	require.Error(t, mut(func(a *Authority) { a.Addresses = []string{"::bad"} }).Validate())
	require.Error(t, mut(func(a *Authority) { a.Addresses = []string{"tcp://127.0.0.1"} }).Validate())
	require.Error(t, mut(func(a *Authority) { a.IdentityPublicKey = nil }).Validate())
	require.Error(t, mut(func(a *Authority) { a.LinkPublicKey = LinkPublicKey{} }).Validate())
}

func TestFixupAndValidateRejects(t *testing.T) {
	cases := map[string]func(f *fixture){
		"no geometry":        func(f *fixture) { f.cfg.SphinxGeometry = nil },
		"bad geometry":       func(f *fixture) { f.cfg.SphinxGeometry = &geo.Geometry{} },
		"no server":          func(f *fixture) { f.cfg.Server = nil },
		"no kem scheme":      func(f *fixture) { f.cfg.Server.WireKEMScheme = "" },
		"unknown kem":        func(f *fixture) { f.cfg.Server.WireKEMScheme = "nosuch" },
		"no sig scheme":      func(f *fixture) { f.cfg.Server.PKISignatureScheme = "" },
		"unknown sig":        func(f *fixture) { f.cfg.Server.PKISignatureScheme = "nosuch" },
		"bad address":        func(f *fixture) { f.cfg.Server.Addresses = []string{"::bad"} },
		"address no port":    func(f *fixture) { f.cfg.Server.Addresses = []string{"tcp://127.0.0.1"} },
		"hostname address":   func(f *fixture) { f.cfg.Server.Addresses = []string{"tcp://example.com:1"} },
		"hostname bind":      func(f *fixture) { f.cfg.Server.BindAddresses = []string{"tcp://example.com:1"} },
		"hostname metrics":   func(f *fixture) { f.cfg.Server.MetricsAddress = "example.com:9100" },
		"relative datadir":   func(f *fixture) { f.cfg.Server.DataDir = "relative" },
		"hostname peer":      func(f *fixture) { f.cfg.Authorities[0].Addresses = []string{"tcp://example.com:1"} },
		"bad log level":      func(f *fixture) { f.cfg.Logging = &Logging{Level: "LOUD"} },
		"negative mu":        func(f *fixture) { f.cfg.Parameters = &Parameters{Mu: -1} },
		"negative lambdap":   func(f *fixture) { f.cfg.Parameters = &Parameters{LambdaP: -1} },
		"negative lambdal":   func(f *fixture) { f.cfg.Parameters = &Parameters{LambdaL: -1} },
		"negative lambdam":   func(f *fixture) { f.cfg.Parameters = &Parameters{LambdaM: -1} },
		"negative lambdar":   func(f *fixture) { f.cfg.Parameters = &Parameters{LambdaR: -1} },
		"too many layers":    func(f *fixture) { f.cfg.Debug = &Debug{Layers: 9} },
		"duplicate node id":  func(f *fixture) { f.cfg.GatewayNodes[0].Identifier = "mix1" },
		"node no id":         func(f *fixture) { f.cfg.Mixes[0].Identifier = "" },
		"node bad idna":      func(f *fixture) { f.cfg.Mixes[0].Identifier = "-bad-" },
		"node no pem":        func(f *fixture) { f.cfg.Mixes[0].IdentityPublicKeyPem = "" },
		"node missing file":  func(f *fixture) { f.cfg.Mixes[0].IdentityPublicKeyPem = "absent.pem" },
		"duplicate node key": func(f *fixture) { f.cfg.Mixes[1].IdentityPublicKeyPem = "mix1.pem" },
		"dup replica id": func(f *fixture) {
			f.cfg.StorageReplicas = append(f.cfg.StorageReplicas, &StorageReplicaNode{Identifier: "rep1", IdentityPublicKeyPem: "rep1.pem", ReplicaID: 2})
		},
		"replica no id":    func(f *fixture) { f.cfg.StorageReplicas[0].Identifier = "" },
		"replica bad idna": func(f *fixture) { f.cfg.StorageReplicas[0].Identifier = "-bad-" },
		"replica no pem":   func(f *fixture) { f.cfg.StorageReplicas[0].IdentityPublicKeyPem = "" },
		"replica same number": func(f *fixture) {
			f.cfg.StorageReplicas = append(f.cfg.StorageReplicas, &StorageReplicaNode{Identifier: "rep2", IdentityPublicKeyPem: "svc1.pem", ReplicaID: 1})
		},
		"replica missing file": func(f *fixture) { f.cfg.StorageReplicas[0].IdentityPublicKeyPem = "absent.pem" },
		"replica dup key": func(f *fixture) {
			f.cfg.StorageReplicas = append(f.cfg.StorageReplicas, &StorageReplicaNode{Identifier: "rep2", IdentityPublicKeyPem: "rep1.pem", ReplicaID: 2})
		},
		"no self pem": func(f *fixture) { require.NoError(t, os.Remove(filepath.Join(f.dir, "identity.public.pem"))) },
		"garbage self pem": func(f *fixture) {
			require.NoError(t, os.WriteFile(filepath.Join(f.dir, "identity.public.pem"), []byte("x"), 0o600))
		},
		"bad peer":        func(f *fixture) { f.cfg.Authorities[0].WireKEMScheme = "" },
		"self not listed": func(f *fixture) { f.cfg.Authorities = nil },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			mut(f)
			require.Error(t, f.cfg.FixupAndValidate(false))
		})
	}
}
