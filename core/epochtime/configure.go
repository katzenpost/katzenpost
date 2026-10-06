// SPDX-License-Identifier: AGPL-3.0-only

package epochtime

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
)

const (
	EnvironmentVariable = "KATZENPOST_EPOCH_DURATION"
	MinPeriod           = 2 * time.Minute
	MaxPeriod           = 7 * 24 * time.Hour
)

func ValidatePeriod(p time.Duration) error {
	if p < MinPeriod || p > MaxPeriod || p%time.Second != 0 {
		return fmt.Errorf("epochtime: epoch duration %v must be whole seconds from %v to %v", p, MinPeriod, MaxPeriod)
	}
	return nil
}

func ValidateConfigured(configured *time.Duration) error {
	if configured == nil {
		return nil
	}
	return ValidatePeriod(*configured)
}

func Configure(configured *time.Duration, warn io.Writer) error {
	if err := ValidateConfigured(configured); err != nil {
		return err
	}
	var p time.Duration
	if configured != nil {
		p = *configured
	}
	return configure(&period, p, os.Getenv(EnvironmentVariable), warn)
}

func configure(v *atomic.Int64, configured time.Duration, env string, warn io.Writer) error {
	p, fromEnv, err := resolvePeriod(configured, env)
	if err != nil {
		return err
	}
	if err := setPeriodOnce(v, p); err != nil {
		return err
	}
	if fromEnv {
		fmt.Fprintf(warn, "epochtime: %s is deprecated, set EpochDuration = %q in the config file instead\n", EnvironmentVariable, p.String())
	}
	return nil
}

func resolvePeriod(configured time.Duration, env string) (time.Duration, bool, error) {
	if configured != 0 {
		if err := ValidatePeriod(configured); err != nil {
			return 0, false, err
		}
		if env == "" {
			return configured, false, nil
		}
		fromEnv, err := time.ParseDuration(env)
		if err != nil || fromEnv != configured {
			return 0, false, fmt.Errorf("epochtime: EpochDuration %v contradicts %s=%q", configured, EnvironmentVariable, env)
		}
		return configured, false, nil
	}
	if env == "" {
		return DefaultPeriod, false, nil
	}
	fromEnv, err := time.ParseDuration(env)
	if err != nil {
		return 0, false, fmt.Errorf("epochtime: %s=%q: %v", EnvironmentVariable, env, err)
	}
	if err := ValidatePeriod(fromEnv); err != nil {
		return 0, false, err
	}
	return fromEnv, true, nil
}

func setPeriodOnce(v *atomic.Int64, p time.Duration) error {
	if v.CompareAndSwap(0, int64(p)) {
		return nil
	}
	if old := time.Duration(v.Load()); old != p {
		return fmt.Errorf("epochtime: epoch duration is already %v, refusing %v", old, p)
	}
	return nil
}
