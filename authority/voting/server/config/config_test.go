// config_test.go - Tests for Katzenpost voting authority config.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package config

import (
	"testing"
	"time"
)

func TestDefaultRetryAttempts(t *testing.T) {
	attempts := DefaultRetryAttempts()
	if attempts < minRetryAttempts {
		t.Errorf("DefaultRetryAttempts() = %d, want >= %d", attempts, minRetryAttempts)
	}
	t.Logf("DefaultRetryAttempts() = %d (minimum: %d)", attempts, minRetryAttempts)
}

func TestDefaultRetryMaxDelay(t *testing.T) {
	maxDelay := DefaultRetryMaxDelay()
	if maxDelay <= 0 {
		t.Errorf("DefaultRetryMaxDelay() = %v, want > 0", maxDelay)
	}
	t.Logf("DefaultRetryMaxDelay() = %v", maxDelay)
}

func TestServerApplyRetryDefaults(t *testing.T) {
	t.Run("empty config gets defaults", func(t *testing.T) {
		cfg := &Server{}
		cfg.applyRetryDefaults()

		if cfg.PeerRetryMaxAttempts != DefaultRetryAttempts() {
			t.Errorf("PeerRetryMaxAttempts = %d, want %d", cfg.PeerRetryMaxAttempts, DefaultRetryAttempts())
		}
		if cfg.PeerRetryBaseDelay != defaultRetryBaseDelay {
			t.Errorf("PeerRetryBaseDelay = %v, want %v", cfg.PeerRetryBaseDelay, defaultRetryBaseDelay)
		}
		if cfg.PeerRetryMaxDelay != DefaultRetryMaxDelay() {
			t.Errorf("PeerRetryMaxDelay = %v, want %v", cfg.PeerRetryMaxDelay, DefaultRetryMaxDelay())
		}
		if cfg.PeerRetryJitter != defaultRetryJitter {
			t.Errorf("PeerRetryJitter = %v, want %v", cfg.PeerRetryJitter, defaultRetryJitter)
		}
	})

	t.Run("explicit values preserved", func(t *testing.T) {
		cfg := &Server{
			PeerRetryMaxAttempts: 25,
			PeerRetryBaseDelay:   3 * time.Second,
			PeerRetryMaxDelay:    45 * time.Second,
			PeerRetryJitter:      0.15,
		}
		cfg.applyRetryDefaults()

		if cfg.PeerRetryMaxAttempts != 25 {
			t.Errorf("PeerRetryMaxAttempts changed to %d", cfg.PeerRetryMaxAttempts)
		}
		if cfg.PeerRetryBaseDelay != 3*time.Second {
			t.Errorf("PeerRetryBaseDelay changed to %v", cfg.PeerRetryBaseDelay)
		}
		if cfg.PeerRetryMaxDelay != 45*time.Second {
			t.Errorf("PeerRetryMaxDelay changed to %v", cfg.PeerRetryMaxDelay)
		}
		if cfg.PeerRetryJitter != 0.15 {
			t.Errorf("PeerRetryJitter changed to %v", cfg.PeerRetryJitter)
		}
	})

	t.Run("jitter capped at 1.0", func(t *testing.T) {
		cfg := &Server{
			PeerRetryJitter: 2.5,
		}
		cfg.applyRetryDefaults()

		if cfg.PeerRetryJitter != 1.0 {
			t.Errorf("PeerRetryJitter = %v, want 1.0 (capped)", cfg.PeerRetryJitter)
		}
	})

	t.Run("negative values get defaults", func(t *testing.T) {
		cfg := &Server{
			PeerRetryMaxAttempts: -5,
			PeerRetryBaseDelay:   -1 * time.Second,
			PeerRetryMaxDelay:    -10 * time.Second,
			PeerRetryJitter:      -0.5,
		}
		cfg.applyRetryDefaults()

		if cfg.PeerRetryMaxAttempts != DefaultRetryAttempts() {
			t.Errorf("negative PeerRetryMaxAttempts not defaulted: %d", cfg.PeerRetryMaxAttempts)
		}
		if cfg.PeerRetryBaseDelay != defaultRetryBaseDelay {
			t.Errorf("negative PeerRetryBaseDelay not defaulted: %v", cfg.PeerRetryBaseDelay)
		}
		if cfg.PeerRetryMaxDelay != DefaultRetryMaxDelay() {
			t.Errorf("negative PeerRetryMaxDelay not defaulted: %v", cfg.PeerRetryMaxDelay)
		}
		if cfg.PeerRetryJitter != defaultRetryJitter {
			t.Errorf("negative PeerRetryJitter not defaulted: %v", cfg.PeerRetryJitter)
		}
	})
}

func TestServerDisableIPv4IPv6(t *testing.T) {
	t.Run("defaults are false", func(t *testing.T) {
		cfg := &Server{}
		if cfg.DisableIPv4 {
			t.Error("DisableIPv4 should default to false")
		}
		if cfg.DisableIPv6 {
			t.Error("DisableIPv6 should default to false")
		}
	})

	t.Run("can be set to true", func(t *testing.T) {
		cfg := &Server{
			DisableIPv4: true,
			DisableIPv6: true,
		}
		if !cfg.DisableIPv4 {
			t.Error("DisableIPv4 should be true")
		}
		if !cfg.DisableIPv6 {
			t.Error("DisableIPv6 should be true")
		}
	})
}

func BenchmarkDefaultRetryAttempts(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DefaultRetryAttempts()
	}
}

func BenchmarkApplyRetryDefaults(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cfg := &Server{}
		cfg.applyRetryDefaults()
	}
}
