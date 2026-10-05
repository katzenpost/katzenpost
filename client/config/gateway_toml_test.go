// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
)

func gatewayTOML(t *testing.T) map[string]interface{} {
	return gatewayTOMLWithScheme(t, "Ed25519")
}

func gatewayTOMLWithScheme(t *testing.T, scheme string) map[string]interface{} {
	idPub, _, err := signSchemes.ByName(scheme).GenerateKey()
	require.NoError(t, err)
	linkPub, _, err := kemschemes.ByName("xwing").GenerateKeyPair()
	require.NoError(t, err)
	return map[string]interface{}{
		"Name":               "gateway1",
		"PKISignatureScheme": scheme,
		"IdentityKey":        signpem.ToPublicPEMString(idPub),
		"WireKEMScheme":      "xwing",
		"LinkKey":            kempem.ToPublicPEMString(linkPub),
		"Addresses":          []interface{}{"tcp://127.0.0.1:1234"},
	}
}

func TestGatewayUnmarshalTOML(t *testing.T) {
	gw := new(Gateway)
	require.NoError(t, gw.UnmarshalTOML(gatewayTOML(t)))
	require.Equal(t, "gateway1", gw.Name)
	require.NotNil(t, gw.IdentityKey)
}

func TestGatewayUnmarshalTOMLHybridScheme(t *testing.T) {
	gw := new(Gateway)
	require.NoError(t, gw.UnmarshalTOML(gatewayTOMLWithScheme(t, testSchemeName)))
	require.Equal(t, "gateway1", gw.Name)
	require.NotNil(t, gw.IdentityKey)
	require.Equal(t, testSchemeName, gw.IdentityKey.Scheme().Name())
}

func TestGatewayUnmarshalTOMLRejectsBadFields(t *testing.T) {
	for name, edit := range map[string]func(map[string]interface{}){
		"empty identity key table": func(d map[string]interface{}) { d["IdentityKey"] = map[string]interface{}{} },
		"missing identity key":     func(d map[string]interface{}) { delete(d, "IdentityKey") },
		"missing name":             func(d map[string]interface{}) { delete(d, "Name") },
		"empty pki scheme":         func(d map[string]interface{}) { d["PKISignatureScheme"] = "" },
		"unknown pki scheme":       func(d map[string]interface{}) { d["PKISignatureScheme"] = "nope" },
		"missing pki scheme":       func(d map[string]interface{}) { delete(d, "PKISignatureScheme") },
		"missing wire kem":         func(d map[string]interface{}) { delete(d, "WireKEMScheme") },
		"empty link key table":     func(d map[string]interface{}) { d["LinkKey"] = map[string]interface{}{} },
	} {
		t.Run(name, func(t *testing.T) {
			d := gatewayTOML(t)
			edit(d)
			var err error
			require.NotPanics(t, func() { err = new(Gateway).UnmarshalTOML(d) })
			require.Error(t, err)
		})
	}
	var err error
	require.NotPanics(t, func() { err = new(Gateway).UnmarshalTOML("not a table") })
	require.Error(t, err)
}
