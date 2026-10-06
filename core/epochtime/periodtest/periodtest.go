// SPDX-License-Identifier: AGPL-3.0-only

package periodtest

import (
	"io"
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
		if err := epochtime.Configure(&p, io.Discard); err != nil {
			t.Fatal(err)
		}
		if got := epochtime.Period(); got != p {
			t.Fatalf("epochtime.Period() is %v, want %v", got, p)
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

type ConfigCase struct {
	Line  string
	Want  time.Duration
	Fails bool
}

var ConfigCases = []ConfigCase{
	{"", 0, false},
	{`EpochDuration = "3m"`, 3 * time.Minute, false},
	{`EpochDuration = "20m"`, 20 * time.Minute, false},
	{`EpochDuration = "2m"`, 2 * time.Minute, false},
	{`EpochDuration = "0s"`, 0, true},
	{`EpochDuration = "90s"`, 0, true},
	{`EpochDuration = "2m0.5s"`, 0, true},
	{`EpochDuration = "-3m"`, 0, true},
	{`EpochDuration = "169h"`, 0, true},
	{`EpochDuration = "soon"`, 0, true},
}

func CheckConfig(t *testing.T, load func(line string) (*time.Duration, error)) {
	t.Helper()
	for _, c := range ConfigCases {
		got, err := load(c.Line)
		if c.Fails {
			if err == nil {
				t.Errorf("%q: loaded, want an error", c.Line)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.Line, err)
			continue
		}
		switch {
		case c.Line == "" && got != nil:
			t.Errorf("absent: got %v, want nil", *got)
		case c.Line != "" && (got == nil || *got != c.Want):
			t.Errorf("%q: got %v, want %v", c.Line, got, c.Want)
		}
	}
}
