// SPDX-License-Identifier: AGPL-3.0-only

package periodtest

import (
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

const childEnv = "EPOCHTIME_PERIODTEST"

var Periods = []time.Duration{20 * time.Minute, 2 * time.Minute}

func Run(t *testing.T, check func(t *testing.T, p time.Duration)) {
	t.Helper()
	if text := os.Getenv(childEnv); text != "" {
		p, err := time.ParseDuration(text)
		if err != nil {
			t.Fatal(err)
		}
		if got := epochtime.Period; got != p {
			t.Fatalf("epochtime.Period is %v, want %v", got, p)
		}
		check(t, p)
		return
	}
	for _, p := range Periods {
		cmd := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.count=1")
		cmd.Env = append(os.Environ(), childEnv+"="+p.String(), "KATZENPOST_EPOCH_DURATION="+p.String())
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("period %v: %v\n%s", p, err, out)
		}
	}
}
