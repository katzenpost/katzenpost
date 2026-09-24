// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
)

func TestVotedParametersKeyIsCanonicalCBOR(t *testing.T) {
	require := require.New(t)
	a := &pki.Document{Mu: 0.001, LambdaP: 0.002, LambdaL: 0.0005, LambdaM: 0.2, LambdaR: 0.3, LambdaG: 1}
	b := &pki.Document{LambdaR: 0.3, LambdaG: 2, Mu: 0.001, LambdaM: 0.2, LambdaL: 0.0005, LambdaP: 0.002, Epoch: 9}

	ka, err := votedParametersKey(a)
	require.NoError(err)
	kb, err := votedParametersKey(b)
	require.NoError(err)
	require.Equal(ka, kb)

	require.Equal("a5624d75fb3f50624dd2f1a9fc674c616d6264614cfb3f40624dd2f1a9fc674c616d6264614dfb3fc999999999999a674c616d62646150fb3f60624dd2f1a9fc674c616d62646152fb3fd3333333333333", hex.EncodeToString([]byte(ka)))

	p, err := votedParametersFromKey(ka)
	require.NoError(err)
	require.Equal(a.Mu, p.Mu)
	require.Equal(a.LambdaP, p.LambdaP)
	require.Equal(a.LambdaL, p.LambdaL)
	require.Equal(a.LambdaM, p.LambdaM)
	require.Equal(a.LambdaR, p.LambdaR)

	c := &pki.Document{Mu: 0.001, LambdaP: 0.002, LambdaL: 0.0005, LambdaM: 0.2, LambdaR: 0.31}
	kc, err := votedParametersKey(c)
	require.NoError(err)
	require.NotEqual(ka, kc)

	_, err = votedParametersFromKey("not cbor")
	require.Error(err)
}
