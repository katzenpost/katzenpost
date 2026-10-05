// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/cert"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func formatTestDoc(t *testing.T) (*cpki.Document, map[[32]byte]string) {
	pub, _, err := schemes.ByName("Ed25519").GenerateKey()
	require.NoError(t, err)
	fp := hash.Sum256From(pub)
	other := [32]byte{0xab}
	return &cpki.Document{
		Epoch:              42,
		GenesisEpoch:       7,
		Mu:                 0.005,
		LambdaP:            0.001,
		Topology:           [][]*cpki.MixDescriptor{{{Name: "mix1"}, {Name: "mix2"}}, {{Name: "mix3"}}},
		GatewayNodes:       []*cpki.MixDescriptor{{Name: "gw1"}},
		ServiceNodes:       []*cpki.MixDescriptor{{Name: "svc1"}, {Name: "svc2"}},
		StorageReplicas:    []*cpki.ReplicaDescriptor{{Name: "rep1"}},
		SharedRandomValue:  []byte{0x01, 0x02},
		SphinxGeometryHash: []byte{0x0a},
		Version:            "v1",
		PKISignatureScheme: "Ed25519",
		Signatures:         map[[32]byte]cert.Signature{fp: {}, other: {}},
	}, map[[32]byte]string{fp: "auth1"}
}

func TestFormatDocumentText(t *testing.T) {
	doc, names := formatTestDoc(t)
	out, err := formatDocument(doc, "text", names)
	require.NoError(t, err)
	for _, want := range []string{
		"epoch 42 (genesis 7)",
		"srv 0102",
		"layer 0: mix1 mix2",
		"layer 1: mix3",
		"gateways: gw1",
		"service nodes: svc1 svc2",
		"replicas: rep1",
		"signers: ab00000000000000000000000000000000000000000000000000000000000000 auth1",
		"mu 0.005",
		"lambdaP 0.001",
		"scheme Ed25519",
	} {
		require.Contains(t, out, want)
	}
}

func TestFormatDocumentJSON(t *testing.T) {
	doc, names := formatTestDoc(t)
	out, err := formatDocument(doc, "json", names)
	require.NoError(t, err)
	var got docView
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Equal(t, newDocView(doc, names), got)
	require.Equal(t, [][]string{{"mix1", "mix2"}, {"mix3"}}, got.Layers)
	require.Equal(t, []string{"ab00000000000000000000000000000000000000000000000000000000000000", "auth1"}, got.Signers)
}

func TestFormatDocumentUnknown(t *testing.T) {
	doc, names := formatTestDoc(t)
	_, err := formatDocument(doc, "yaml", names)
	require.Error(t, err)
}
