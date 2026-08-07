// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
)

func TestComputeSharedRandomLogsUnknownCommitterHash(t *testing.T) {
	st := &state{threshold: 2}
	out := fileLogged(t, st)
	pub, _, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	pk := hash.Sum256From(pub)
	_, err = st.computeSharedRandom(1, map[[publicKeyHashSize]byte][]byte{pk: {1}}, nil)
	require.Error(t, err)
	require.Contains(t, out(), fmt.Sprintf("from %x", pk))
}
