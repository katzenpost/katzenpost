// SPDX-License-Identifier: AGPL-3.0-only

package epochtime

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPeriodDefault(t *testing.T) {
	require.Equal(t, 20*time.Minute, Period())
}

func TestEnvironmentAloneDoesNotSetThePeriod(t *testing.T) {
	if os.Getenv("EPOCHTIME_CHILD") != "" {
		require.Equal(t, 20*time.Minute, Period())
		return
	}
	for _, d := range []string{"2m", "90s", "soon"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestEnvironmentAloneDoesNotSetThePeriod$", "-test.count=1")
		cmd.Env = append(os.Environ(), EnvironmentVariable+"="+d, "EPOCHTIME_CHILD=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
}
