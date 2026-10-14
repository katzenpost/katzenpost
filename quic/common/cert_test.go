// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestListenerCertIsUnremarkable(t *testing.T) {
	leaf, err := x509.ParseCertificate(GenerateTLSConfig().Certificates[0].Certificate[0])
	require.NoError(t, err)
	now := time.Now()
	require.True(t, leaf.NotBefore.Before(now) && leaf.NotAfter.After(now), "validity [%v, %v] does not contain now", leaf.NotBefore, leaf.NotAfter)
	require.GreaterOrEqual(t, leaf.SerialNumber.BitLen(), 64, "serial %v", leaf.SerialNumber)
}

func TestListenerCertFollowsTheEpochWindow(t *testing.T) {
	leaf, err := x509.ParseCertificate(GenerateTLSConfig().Certificates[0].Certificate[0])
	require.NoError(t, err)
	epoch := CurrentEpoch()
	require.False(t, leaf.NotAfter.After(epochStart(epoch+2)), "NotAfter %v is past the end of epoch %d", leaf.NotAfter, epoch+1)
	require.False(t, leaf.NotBefore.Before(epochStart(epoch-1)), "NotBefore %v is before the start of epoch %d", leaf.NotBefore, epoch-1)
}
