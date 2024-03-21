// document_test.go - Document s11n tests.
// Copyright (C) 2017  Yawning Angel, masala, David Stainton
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

package pki

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/cert"
)

var testingSchemeName = "xwing"
var testingScheme = schemes.ByName(testingSchemeName)

func genDescriptor(require *require.Assertions, idx int, provider bool) (*MixDescriptor, []byte) {
	d := new(MixDescriptor)
	d.Name = fmt.Sprintf("gen%d.example.net", idx)
	d.Addresses = map[Transport][]string{
		TransportTCPv4: []string{fmt.Sprintf("192.0.2.%d:4242", idx)},
	}
	d.Provider = provider
	d.Epoch = debugTestEpoch
	d.Version = DescriptorVersion
	d.LoadWeight = 23

	identityPub, identityPriv, err := cert.Scheme.GenerateKey()
	require.NoError(err)

	d.IdentityKey, err = identityPub.MarshalBinary()
	require.NoError(err)

	scheme := testingScheme
	linkKey, _, err := scheme.GenerateKeyPair()
	require.NoError(err)
	d.LinkKey, err = linkKey.MarshalBinary()
	require.NoError(err)
	d.MixKeys = make(map[uint64][]byte)
	for e := debugTestEpoch; e < debugTestEpoch+3; e++ {
		mPriv, err := ecdh.NewKeypair(rand.Reader)
		require.NoError(err, "[%d]: ecdh.NewKeypair()", e)
		d.MixKeys[uint64(e)] = mPriv.Public().Bytes()
	}
	if provider {
		d.Kaetzchen = make(map[string]map[string]interface{})
		d.Kaetzchen["miau"] = map[string]interface{}{
			"endpoint":  "+miau",
			"miauCount": idx,
		}
	}
	err = IsDescriptorWellFormed(d, debugTestEpoch)
	require.NoError(err, "IsDescriptorWellFormed(good)")

	signed, err := SignDescriptor(identityPriv, identityPub, d)
	require.NoError(err, "SignDescriptor()")

	return d, []byte(signed)
}

func TestDocument(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	// Generate a random signing key.
	idPub, k, err := cert.Scheme.GenerateKey()
	require.NoError(err)

	testSendRate := uint64(3)
	sharedRandomCommit := make([]byte, SharedRandomLength)
	binary.BigEndian.PutUint64(sharedRandomCommit[:8], debugTestEpoch)

	// Generate a Document.
	doc := &Document{
		Epoch:              debugTestEpoch,
		GenesisEpoch:       debugTestEpoch,
		SendRatePerMinute:  testSendRate,
		Topology:           make([][]*MixDescriptor, 3),
		Mu:                 0.42,
		MuMaxDelay:         23,
		LambdaP:            0.69,
		LambdaPMaxDelay:    17,
		SharedRandomCommit: make(map[[PublicKeyHashSize]byte][]byte),
		SharedRandomReveal: make(map[[PublicKeyHashSize]byte][]byte),
		SharedRandomValue:  make([]byte, SharedRandomValueLength),
		Version:            DocumentVersion,
	}
	idx := 1
	for l := 0; l < 3; l++ {
		for i := 0; i < 5; i++ {
			provider := false
			_, rawDesc := genDescriptor(require, idx, provider)
			d := new(MixDescriptor)
			err := d.UnmarshalBinary(rawDesc)
			require.NoError(err)
			foo, err := d.MarshalBinary()
			require.NoError(err)
			require.True(bytes.Equal(foo, rawDesc))
			doc.Topology[l] = append(doc.Topology[l], d)
			idx++
		}
	}
	for i := 0; i < 3; i++ {
		provider := true
		_, rawDesc := genDescriptor(require, idx, provider)
		d := new(MixDescriptor)
		err := d.UnmarshalBinary(rawDesc)
		require.NoError(err)
		foo, err := d.MarshalBinary()
		require.NoError(err)
		require.True(bytes.Equal(foo, rawDesc))
		doc.Providers = append(doc.Providers, d)
		idx++
	}

	// Serialize and sign.
	signed, err := SignDocument(k, idPub, doc)
	require.NoError(err, "SignDocument()")

	// Validate and deserialize.
	ddoc, err := ParseDocument(signed)
	require.NoError(err, "ParseDocument()")
	require.Equal(doc.Epoch, ddoc.Epoch, "ParseDocument(): Epoch")
	require.Equal(doc.SendRatePerMinute, testSendRate, "ParseDocument(): SendRatePerMinute")
	require.Equal(doc.Mu, ddoc.Mu, "ParseDocument(): Mu")
	require.Equal(doc.MuMaxDelay, ddoc.MuMaxDelay, "ParseDocument(): MuMaxDelay")
	require.Equal(doc.LambdaP, ddoc.LambdaP, "ParseDocument(): LambdaP")
	require.Equal(doc.LambdaPMaxDelay, ddoc.LambdaPMaxDelay, "ParseDocument(): LambdaPMaxDelay")
	require.Equal(doc.LambdaL, ddoc.LambdaL, "ParseDocument(): LambdaL")
	require.Equal(doc.LambdaLMaxDelay, ddoc.LambdaLMaxDelay, "ParseDocument(): LambdaLMaxDelay")
	require.Equal(doc.LambdaD, ddoc.LambdaD, "ParseDocument(): LambdaD")
	require.Equal(doc.LambdaDMaxDelay, ddoc.LambdaDMaxDelay, "ParseDocument(): LambdaDMaxDelay")
	require.Equal(doc.LambdaM, ddoc.LambdaM, "ParseDocument(): LambdaM")
	require.Equal(doc.LambdaMMaxDelay, ddoc.LambdaMMaxDelay, "ParseDocument(): LambdaMMaxDelay")
	require.Equal(doc.SharedRandomValue, ddoc.SharedRandomValue, "ParseDocument(): SharedRandomValue")
	require.Equal(doc.PriorSharedRandom, ddoc.PriorSharedRandom, "ParseDocument(): PriorSharedRandom")
	require.Equal(doc.SharedRandomCommit, ddoc.SharedRandomCommit, "ParseDocument(): SharedRandomCommit")
	require.Equal(doc.SharedRandomReveal, ddoc.SharedRandomReveal, "ParseDocument(): SharedRandomReveal")
	require.Equal(doc.Version, ddoc.Version, "ParseDocument(): Version")

	// Test that marshalling doesn't mutate the document:
	// (It would have been nice to check that SignDocument was idempotent,
	// but it seems SPHINCS+ uses randomness?
	tmpDocBytes := signed
	for i := 0; i < 4; i++ {
		tmpDoc, err := ParseDocument(tmpDocBytes)
		require.Equal(nil, err)
		require.Equal(ddoc, tmpDoc)
		tmpDocBytes, err := tmpDoc.MarshalBinary()
		require.Equal(nil, err)
		require.Equal(signed, tmpDocBytes)
	}

	// check that MixDescriptors are signed correctly and can be deserialized and reserialized from the Document
	for l, layer := range ddoc.Topology {
		for i, node := range layer {
			nnode := doc.Topology[l][i] // compare the serialization of descriptors before/after
			otherDesc, err := nnode.MarshalBinary()
			require.NoError(err)
			rawDesc, err := node.MarshalBinary()
			require.NoError(err)
			_, err = VerifyDescriptor(rawDesc)
			require.NoError(err)
			_, err = VerifyDescriptor(otherDesc)
			require.NoError(err)
			require.True(bytes.Equal(otherDesc, rawDesc)) // require the serialization be the same
		}
	}

	// check that Providers are the same
	for i, provider := range ddoc.Providers {
		d, err := provider.MarshalBinary()
		require.NoError(err)
		d2, err := doc.Providers[i].MarshalBinary()
		require.NoError(err)
		require.True(bytes.Equal(d, d2))
	}
}
