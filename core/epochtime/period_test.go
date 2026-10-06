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
	if os.Getenv("KATZENPOST_EPOCH_DURATION") != "" {
		t.Skip("KATZENPOST_EPOCH_DURATION is set")
	}
	require.Equal(t, 20*time.Minute, Period())
}

func TestPeriodFromEnvironment(t *testing.T) {
	if want := os.Getenv("EPOCHTIME_WANT_PERIOD"); want != "" {
		d, err := time.ParseDuration(want)
		require.NoError(t, err)
		require.Equal(t, d, Period())
		return
	}
	for _, d := range []string{"2m", "90s", "20m"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPeriodFromEnvironment$")
		cmd.Env = append(os.Environ(), "KATZENPOST_EPOCH_DURATION="+d, "EPOCHTIME_WANT_PERIOD="+d)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
}
