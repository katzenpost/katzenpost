// SPDX-License-Identifier: AGPL-3.0-only

package scheduler

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/constants"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

type hopRecorder struct {
	seen chan [sConstants.NodeIDLength]byte
}

func (c *hopRecorder) Halt()        {}
func (c *hopRecorder) ForceUpdate() {}

func (c *hopRecorder) DispatchPacket(pkt *packet.Packet) {
	pkt.Dispose()
}

func (c *hopRecorder) IsValidForwardDest(id *[sConstants.NodeIDLength]byte) bool {
	c.seen <- *id
	return true
}

type maxDelayGlue struct {
	mockGlue
	cfg   *config.Config
	logBE *log.Backend
	conn  *hopRecorder
}

func (g *maxDelayGlue) Config() *config.Config    { return g.cfg }
func (g *maxDelayGlue) LogBackend() *log.Backend  { return g.logBE }
func (g *maxDelayGlue) Connector() glue.Connector { return g.conn }

type maxDelayHarness struct {
	sch     glue.Scheduler
	conn    *hopRecorder
	geo     *geo.Geometry
	logPath string
	nextID  atomic.Uint64
}

func newMaxDelayHarness(t *testing.T) *maxDelayHarness {
	return newMaxDelayHarnessWith(t, func(*config.Config) {})
}

func newMaxDelayHarnessWith(t *testing.T, adjust func(*config.Config)) *maxDelayHarness {
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	cfg := &config.Config{
		SphinxGeometry: g,
		Server: &config.Server{
			Identifier:         "mix",
			WireKEM:            "xwing",
			PKISignatureScheme: "Ed25519",
			Addresses:          []string{"tcp://127.0.0.1:1"},
			DataDir:            t.TempDir(),
		},
		PKI: &config.PKI{Voting: &config.Voting{}},
	}
	require.NoError(t, cfg.FixupAndValidate())
	adjust(cfg)

	logPath := filepath.Join(t.TempDir(), "scheduler.log")
	logBE, err := log.New(logPath, "INFO", false)
	require.NoError(t, err)
	t.Cleanup(func() { logBE.Close() })

	conn := &hopRecorder{seen: make(chan [sConstants.NodeIDLength]byte, 16)}
	sch, err := New(&maxDelayGlue{cfg: cfg, logBE: logBE, conn: conn})
	require.NoError(t, err)
	t.Cleanup(sch.Halt)
	return &maxDelayHarness{sch: sch, conn: conn, geo: g, logPath: logPath}
}

func (h *maxDelayHarness) logged(t *testing.T) string {
	t.Helper()
	h.accepts(t, 0)
	b, err := os.ReadFile(h.logPath)
	require.NoError(t, err)
	return string(b)
}

func (h *maxDelayHarness) send(t *testing.T, delay time.Duration) [sConstants.NodeIDLength]byte {
	pkt, err := packet.New(make([]byte, h.geo.PacketLength), h.geo)
	require.NoError(t, err)
	var id [sConstants.NodeIDLength]byte
	binary.BigEndian.PutUint64(id[:], h.nextID.Add(1))
	pkt.NextNodeHop = &commands.NextNodeHop{ID: id}
	pkt.Delay = delay
	h.sch.OnPacket(pkt)
	return id
}

func (h *maxDelayHarness) accepts(t *testing.T, delay time.Duration) bool {
	t.Helper()
	probe := h.send(t, delay)
	marker := h.send(t, 0)
	accepted := false
	for {
		select {
		case id := <-h.conn.seen:
			switch id {
			case probe:
				accepted = true
			case marker:
				return accepted
			default:
				t.Fatalf("unexpected hop %x", id)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("zero delay marker never reached the forward check after a %v probe", delay)
		}
	}
}

func (h *maxDelayHarness) requireAccepts(t *testing.T, delay time.Duration) {
	t.Helper()
	require.True(t, h.accepts(t, delay), "a %v delay must be accepted", delay)
}

func (h *maxDelayHarness) requireDrops(t *testing.T, delay time.Duration) {
	t.Helper()
	require.False(t, h.accepts(t, delay), "a %v delay must be dropped", delay)
}

func TestSchedulerMaxDelayFallbackBeforeConsensus(t *testing.T) {
	h := newMaxDelayHarness(t)
	h.requireAccepts(t, 27632*time.Millisecond)
	h.requireDrops(t, 27633*time.Millisecond)
	h.requireDrops(t, time.Minute)
}

func TestSchedulerMaxDelayUnsetFallbackIsBuiltin(t *testing.T) {
	for _, fallback := range []int{0, -1} {
		h := newMaxDelayHarnessWith(t, func(cfg *config.Config) { cfg.Debug.MixMaxDelayFallback = fallback })
		h.requireAccepts(t, 27632*time.Millisecond)
		h.requireDrops(t, 27633*time.Millisecond)
		h.sch.OnNewMixMaxDelay(5000)
		h.sch.OnNewMixMaxDelay(0)
		h.requireAccepts(t, 27632*time.Millisecond)
		h.requireDrops(t, 27633*time.Millisecond)
	}
}

func TestSchedulerMaxDelayFallbackOnZeroConsensus(t *testing.T) {
	h := newMaxDelayHarness(t)
	h.sch.OnNewMixMaxDelay(5000)
	h.requireDrops(t, 10*time.Second)
	h.sch.OnNewMixMaxDelay(0)
	h.requireAccepts(t, 20*time.Second)
	h.requireDrops(t, time.Minute)
}

func TestSchedulerMaxDelayConsensusOverridesFallback(t *testing.T) {
	h := newMaxDelayHarness(t)
	h.sch.OnNewMixMaxDelay(5000)
	h.requireAccepts(t, 5*time.Second)
	h.requireDrops(t, 5001*time.Millisecond)
	h.sch.OnNewMixMaxDelay(90000)
	h.requireAccepts(t, time.Minute)
	h.requireDrops(t, 91*time.Second)
}

func TestSchedulerMaxDelayConsensusAboveCeiling(t *testing.T) {
	ceiling := schedulerCeiling()
	h := newMaxDelayHarness(t)
	h.sch.OnNewMixMaxDelay(uint64((2 * ceiling) / time.Millisecond))
	h.requireAccepts(t, ceiling)
	h.requireDrops(t, ceiling+time.Millisecond)
	h.sch.OnNewMixMaxDelay(math.MaxUint64)
	h.requireAccepts(t, ceiling)
	h.requireDrops(t, ceiling+time.Millisecond)
}

func schedulerCeiling() time.Duration {
	return epochtime.Period() * constants.NumMixKeys
}

func TestSchedulerLogsBuiltinMaxDelayAtStartup(t *testing.T) {
	for _, fallback := range []int{0, 27632} {
		h := newMaxDelayHarnessWith(t, func(cfg *config.Config) { cfg.Debug.MixMaxDelayFallback = fallback })
		logged := h.logged(t)
		want := fmt.Sprintf("INFO scheduler: Per-hop max delay built-in 27.632s (SafetyCap of Mu 0.001), configured fallback %d ms, ceiling %v.", fallback, schedulerCeiling())
		require.Contains(t, logged, want)
		require.NotContains(t, logged, "WARN")
	}
}

func TestSchedulerWarnsOnWildFallback(t *testing.T) {
	for _, tc := range []struct {
		fallback int
		wild     bool
	}{
		{6907, true},
		{6908, false},
		{110528, false},
		{110529, true},
	} {
		h := newMaxDelayHarnessWith(t, func(cfg *config.Config) { cfg.Debug.MixMaxDelayFallback = tc.fallback })
		logged := h.logged(t)
		want := fmt.Sprintf("WARN scheduler: Configured MixMaxDelayFallback %d ms differs from the built-in 27.632s by more than a factor of 4.", tc.fallback)
		if tc.wild {
			require.Equal(t, 1, strings.Count(logged, want), "fallback %d", tc.fallback)
		} else {
			require.NotContains(t, logged, "WARN", "fallback %d", tc.fallback)
		}
	}
}

func TestSchedulerWarnsOnWildConsensusOncePerChange(t *testing.T) {
	h := newMaxDelayHarness(t)
	for _, ms := range []uint64{5000, 5000, 90000, 0, 6908, 110528, 5000, math.MaxUint64, math.MaxUint64} {
		h.sch.OnNewMixMaxDelay(ms)
	}
	logged := h.logged(t)
	warn := func(ms uint64) string {
		return fmt.Sprintf("WARN scheduler: Consensus MixMaxDelay %d ms differs from the built-in 27.632s by more than a factor of 4.", ms)
	}
	require.Equal(t, 2, strings.Count(logged, warn(5000)))
	require.Equal(t, 1, strings.Count(logged, warn(math.MaxUint64)))
	require.Equal(t, 3, strings.Count(logged, "WARN"))
}
