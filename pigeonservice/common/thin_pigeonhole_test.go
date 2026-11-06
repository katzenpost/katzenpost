// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

const (
	routerCapability    = "voucher_router"
	directoryCapability = "service_directory"
)

func TestServiceParamsReadsAdvertizedData(t *testing.T) {
	key := []byte{1, 2, 3}
	desc := &cpki.MixDescriptor{
		Kaetzchen: map[string]map[string]interface{}{
			routerCapability: {"endpoint": routerCapability},
		},
		KaetzchenAdvertizedData: map[string]map[string]interface{}{
			routerCapability: {ParamNIKEScheme: DefaultNIKE.Name(), ParamPublicKey: key},
		},
	}
	params := serviceParams(desc, routerCapability)
	require.Equal(t, routerCapability, params["endpoint"])
	require.Equal(t, DefaultNIKE.Name(), params[ParamNIKEScheme])
	require.Equal(t, key, params[ParamPublicKey])
	require.Empty(t, serviceParams(desc, directoryCapability))
}
