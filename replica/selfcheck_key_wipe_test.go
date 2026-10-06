// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

func TestMKEMSelfCheckWipesItsKeys(t *testing.T) {
	s := &trackingNikeScheme{Scheme: x25519.Scheme(rand.Reader)}

	result := measureMKEM(logging.MustGetLogger("selfcheck-wipe-test"), mkem.NewScheme(s), s)
	require.Greater(t, result.OpsPerSecPerCore, 0.0)
	require.Len(t, s.keys, 2)

	s.requireAllWiped(t, "the MKEM self check")
}
