// document_test.go - Document s11n tests.
// Copyright (C) 2017  Yawning Angel
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
	"fmt"
	"testing"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/pki"
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
	identityPriv, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err, "eddsa.NewKeypair()")
	d.IdentityKey = identityPriv.PublicKey()
	linkPriv, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "ecdh.NewKeypair()")
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
	err = IsDescriptorWellFormed(d, debugTestEpoch)
	require.NoError(err, "IsDescriptorWellFormed(good)")

	signed, err := SignDescriptor(identityPriv, d)
	require.NoError(err, "SignDescriptor()")

	return d, []byte(signed)
}

func TestDocument(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Generate a random signing key.
	k, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err, "eddsa.NewKeypair()")

	// Generate a Document.
	doc := &Document{
		Epoch:           debugTestEpoch,
		Topology:        make([][][]byte, 3),
		MixLambda:       0.42,
		MixMaxDelay:     23,
		SendLambda:      0.69,
		SendShift:       15000,
		SendMaxInterval: 17,
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

	t.Logf("Document: '%v'", doc)

	// Serialize and sign.
	signed, err := SignDocument(k, doc)
	require.NoError(err, "SignDocument()")

	t.Logf("signed document: '%v':", signed)

	// Validate and deserialize.
	ddoc, err := VerifyAndParseDocument([]byte(signed), k.PublicKey())
	require.NoError(err, "VerifyAndParseDocument()")
	require.Equal(doc.Epoch, ddoc.Epoch, "VerifyAndParseDocument(): Epoch")

	require.Equal(doc.MixLambda, ddoc.MixLambda, "VerifyAndParseDocument(): MixLambda")
	require.Equal(doc.MixMaxDelay, ddoc.MixMaxDelay, "VerifyAndParseDocument(): MixMaxDelay")
	require.Equal(doc.SendLambda, ddoc.SendLambda, "VerifyAndParseDocument(): SendLambda")
	require.Equal(doc.SendShift, ddoc.SendShift, "VerifyAndParseDocument(): SendShift")
	require.Equal(doc.SendMaxInterval, ddoc.SendMaxInterval, "VerifyAndParseDocument(): SendMaxInterval")

	t.Logf("Deserialized document: '%v'", ddoc)

	// TODO: Ensure the descriptors are sane.
	_ = assert
}
