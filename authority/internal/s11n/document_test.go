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

package s11n

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func genDescriptor(require *require.Assertions, idx int, layer int) (*pki.MixDescriptor, []byte) {
	d := new(pki.MixDescriptor)
	d.Name = fmt.Sprintf("gen%d.example.net", idx)
	d.Addresses = map[pki.Transport][]string{
		pki.TransportTCPv4: []string{fmt.Sprintf("192.0.2.%d:4242", idx)},
	}
	d.Layer = uint8(layer)
	d.LoadWeight = 23
	identityPriv, identityPub := cert.Scheme.NewKeypair()
	d.IdentityKey = identityPub
	scheme := wire.DefaultScheme
	linkPriv := scheme.GenerateKeypair(rand.Reader)
	d.LinkKey = linkPriv.PublicKey()
	d.MixKeys = make(map[uint64]*ecdh.PublicKey)
	for e := debugTestEpoch; e < debugTestEpoch+3; e++ {
		mPriv, err := ecdh.NewKeypair(rand.Reader)
		require.NoError(err, "[%d]: ecdh.NewKeypair()", e)
		d.MixKeys[uint64(e)] = mPriv.PublicKey()
	}
	if layer == pki.LayerProvider {
		d.Kaetzchen = make(map[string]map[string]interface{})
		d.Kaetzchen["miau"] = map[string]interface{}{
			"endpoint":  "+miau",
			"miauCount": idx,
		}
	}
	err := IsDescriptorWellFormed(d, debugTestEpoch)
	require.NoError(err, "IsDescriptorWellFormed(good)")

	signed, err := SignDescriptor(identityPriv, d)
	require.NoError(err, "SignDescriptor()")

	return d, []byte(signed)
}

func TestDocument(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Generate a random signing key.
	k, idPub := cert.Scheme.NewKeypair()

	testSendRate := uint64(3)
	sharedRandomCommit := make([]byte, SharedRandomLength)
	binary.BigEndian.PutUint64(sharedRandomCommit[:8], debugTestEpoch)

	// Generate a Document.
	doc := &Document{
		Epoch:              debugTestEpoch,
		GenesisEpoch:       debugTestEpoch,
		SendRatePerMinute:  testSendRate,
		Topology:           make([][][]byte, 3),
		Mu:                 0.42,
		MuMaxDelay:         23,
		LambdaP:            0.69,
		LambdaPMaxDelay:    17,
		SharedRandomCommit: sharedRandomCommit,
		SharedRandomValue:  make([]byte, SharedRandomValueLength),
	}
	idx := 1
	for l := 0; l < 3; l++ {
		for i := 0; i < 5; i++ {
			_, rawDesc := genDescriptor(require, idx, 0)
			doc.Topology[l] = append(doc.Topology[l], rawDesc)
			idx++
		}
	}
	for i := 0; i < 3; i++ {
		_, rawDesc := genDescriptor(require, idx, pki.LayerProvider)
		doc.Providers = append(doc.Providers, rawDesc)
		idx++
	}

	// Serialize and sign.
	signed, err := SignDocument(k, doc)
	require.NoError(err, "SignDocument()")

	// Validate and deserialize.
	ddoc, err := VerifyAndParseDocument([]byte(signed), idPub)
	require.NoError(err, "VerifyAndParseDocument()")
	require.Equal(doc.Epoch, ddoc.Epoch, "VerifyAndParseDocument(): Epoch")
	require.Equal(doc.SendRatePerMinute, testSendRate, "VerifyAndParseDocument(): SendRatePerMinute")
	require.Equal(doc.Mu, ddoc.Mu, "VerifyAndParseDocument(): Mu")
	require.Equal(doc.MuMaxDelay, ddoc.MuMaxDelay, "VerifyAndParseDocument(): MuMaxDelay")
	require.Equal(doc.LambdaP, ddoc.LambdaP, "VerifyAndParseDocument(): LambdaP")
	require.Equal(doc.LambdaPMaxDelay, ddoc.LambdaPMaxDelay, "VerifyAndParseDocument(): LambdaPMaxDelay")
	require.Equal(doc.LambdaL, ddoc.LambdaL, "VerifyAndParseDocument(): LambdaL")
	require.Equal(doc.LambdaLMaxDelay, ddoc.LambdaLMaxDelay, "VerifyAndParseDocument(): LambdaLMaxDelay")
	require.Equal(doc.LambdaD, ddoc.LambdaD, "VerifyAndParseDocument(): LambdaD")
	require.Equal(doc.LambdaDMaxDelay, ddoc.LambdaDMaxDelay, "VerifyAndParseDocument(): LambdaDMaxDelay")
	require.Equal(doc.LambdaM, ddoc.LambdaM, "VerifyAndParseDocument(): LambdaM")
	require.Equal(doc.LambdaMMaxDelay, ddoc.LambdaMMaxDelay, "VerifyAndParseDocument(): LambdaMMaxDelay")

	t.Logf("Deserialized document: '%v'", ddoc)

	// TODO: Ensure the descriptors are sane.
	_ = assert
}
