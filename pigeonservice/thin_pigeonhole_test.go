// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"testing"

	"github.com/stretchr/testify/require"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestServiceParamsReadsAdvertizedData(t *testing.T) {
	key := []byte{1, 2, 3}
	desc := &cpki.MixDescriptor{
		Kaetzchen: map[string]map[string]interface{}{
			RouterCapability: {"endpoint": RouterCapability},
		},
		KaetzchenAdvertizedData: map[string]map[string]interface{}{
			RouterCapability: {ParamNIKEScheme: DefaultNIKE.Name(), ParamPublicKey: key},
		},
	}
	params := serviceParams(desc, RouterCapability)
	require.Equal(t, RouterCapability, params["endpoint"])
	require.Equal(t, DefaultNIKE.Name(), params[ParamNIKEScheme])
	require.Equal(t, key, params[ParamPublicKey])
	require.Empty(t, serviceParams(desc, DirectoryCapability))
}
