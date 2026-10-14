// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"fmt"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestPinMismatchOptionValidates(t *testing.T) {
	for _, value := range []string{"", "fallback", "strict"} {
		var o Options
		require.NoError(t, toml.Unmarshal([]byte(fmt.Sprintf("PinMismatch = %q", value)), &o))
		require.NoError(t, o.Validate(), "PinMismatch = %q", value)
	}
	for _, value := range []string{"never", "Strict"} {
		var o Options
		require.NoError(t, toml.Unmarshal([]byte(fmt.Sprintf("PinMismatch = %q", value)), &o))
		require.Error(t, o.Validate(), "PinMismatch = %q", value)
	}
}
