// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

// observation is one ping's outcome together with the hops it travelled.
// Routes are empty when the daemon did not report them, which is not the
// same as a route of no hops, so an observation without routes contributes
// to the totals and to nothing else.
type observation struct {
	at      time.Time
	ok      bool
	forward []string
	back    []string
}

// attribution collects the outcome and route of every packet in a batch and
// turns them into per-node statements about loss.
//
// # The model
//
// A round trip visits the gateway, one mix from each layer, the service node,
// one mix from each layer again, and the gateway once more. When a packet does
// not come back, every node on its route is a suspect and none is convicted:
// the observation is a single bit about nine nodes. Only across many packets,
// with the mixes redrawn each time, does the evidence separate.
//
// # What a single run can and cannot identify
//
// Each group contributes a fixed number of hops to every route: the gateway
// twice, each mix layer twice, the service node once. A group's overall level
// is therefore confounded with every other group's, and no quantity of packets
// will separate them, because nothing in the data varies that could. What does
// vary is which member of a layer was drawn, so differences within a layer are
// estimable even though the layers' levels are not.
//
// That is why every comparison here is against the rest of a node's own group.
// Its peers sit behind the identical baseline, so the comparison cancels it. A
// comparison against a network-wide average would instead carry the confounded
// baseline into the estimate and quietly attribute it to whichever node was
// being measured.
//
// So a run pinned to one gateway and one service node can say which mix in a
// layer is worse than its neighbours, can say what the overall loss rate is,
// and can say nothing whatever about the gateway. Rotating services makes the
// service set vary and brings it into the estimable set too, which is what
// --rotate-services is for.
//
// # Why exposure means met-this-node-and-not-its-neighbour
//
// A route draws one node from each layer going out and another coming back, so
// most packets that touch a healthy node also touch its faulty neighbour, fail
// because of the neighbour, and would be charged to both. On a simulated layer
// with one node dropping 15%, counting every packet that touched a node gave
// the innocent partner 12.4% against the culprit's 15.9%: three points of
// difference where the truth was fifteen.
//
// So a node's count here is restricted to packets that met it and no other
// member of its group, which no neighbour was in a position to spoil. It costs
// sample size, since a packet whose two draws differ is used by neither side,
// but an undiluted comparison on half the packets beats a diluted one on all
// of them by a wide margin. See exclusiveTally.
//
// # What this cannot see
//
// The comparison assumes a node's behaviour holds still for as long as it is
// measured. Real loss does not oblige. If two nodes each fail badly at
// different times, the run-long averages come out equal and the comparison
// reports nothing whatever; simulated, it missed a culprit that swapped
// halfway through in two hundred runs out of two hundred. A node that fails
// badly but briefly is diluted the same way and was caught under one time in
// ten.
//
// scanWindows exists for that, repeating the comparison over stretches of the
// run. It recovers the swapping culprit reliably and the brief one about half
// the time. Half is not all, and a batch that ends with no finding has shown
// an absence of evidence rather than evidence of absence.
//
// # Why intervals rather than point estimates
//
// Per-node failure counts are small and frequently zero, where a point
// estimate is close to meaningless on its own: three failures in twenty
// packets is 15% and is also entirely consistent with 5% or with 35%. See
// wilson for why the usual textbook interval will not serve either.
//
// # How much data it takes
//
// Interval width shrinks roughly as the reciprocal square root of exposure, so
// telling a node running at 6% apart from a 2% baseline needs on the order of
// a thousand packets through it. In a two-member layer a node sees about half
// the batch, so that is a couple of thousand packets. A short run is not a
// clean bill of health; it is an absence of evidence, and the intervals say so
// by remaining wide enough to straddle zero.
//
// Pings run concurrently, so record is called from many goroutines and takes
// the lock; the report is produced once, after the batch has drained.
type attribution struct {
	mu  sync.Mutex
	obs []observation
}

func (a *attribution) record(o observation) {
	a.mu.Lock()
	a.obs = append(a.obs, o)
	a.mu.Unlock()
}

// zScore95 is the standard normal quantile for a two-sided 95% interval.
const zScore95 = 1.959964

// wilson returns the Wilson score interval for k failures in n trials.
//
// It answers "we saw this rate, but how sure are we", which for the small
// counts this tool works with is the only question worth asking.
//
// The obvious way to build such a range is to take the rate you observed and
// spread it either side by some multiple of its standard error. That method
// has a fatal defect here. With no failures at all it computes a spread of
// zero and returns the range [0%, 0%], claiming perfect certainty on the
// strength of having seen nothing go wrong. It is also too narrow whenever the
// packet count is small or the rate is near zero, which describes most of what
// gets measured here.
//
// Wilson's method asks the question the other way round. Rather than spreading
// a range around the rate that happened to come up, it asks which true rates
// would make that observation unsurprising, and keeps those. For no failures
// in a hundred packets it answers [0%, 3.7%]: nothing has gone wrong yet, and
// a node quietly dropping one packet in twenty-seven is still entirely
// consistent with what was seen. The arithmetic below is the closed-form
// solution to that question; it has no free parameters to tune.
//
// z sets the confidence: it is how many standard deviations wide the range is,
// and 1.96 is the value that yields 95%.
func wilson(k, n int) (lo, hi float64) {
	return wilsonZ(k, n, zScore95)
}

// wilsonZ is wilson at an arbitrary confidence, expressed as the z that
// corresponds to it. Scanning many time windows needs a stricter z than 95%,
// because testing repeatedly gives chance more opportunities to produce a
// striking result; see zForTests.
func wilsonZ(k, n int, z float64) (lo, hi float64) {
	if n == 0 {
		return 0, 0
	}
	p := float64(k) / float64(n)
	nf := float64(n)
	denom := 1 + z*z/nf
	center := (p + z*z/(2*nf)) / denom
	half := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf)) / denom
	return math.Max(0, center-half), math.Min(1, center+half)
}

// diffInterval returns a 95% interval for p1-p2 by Newcombe's score method.
//
// The tempting shortcut is to spread a range around each rate and combine the
// spreads. That inherits the defect described on wilson: when either side has
// seen no failures its contribution collapses to nothing and the answer comes
// out far too confident.
//
// Newcombe's method uses the two Wilson ranges as they are. The difference is
// at its most negative when the first rate sits at the bottom of its plausible
// range and the second at the top, so those two distances bound how far the
// difference can stray. They are combined as the hypotenuse of a right
// triangle rather than added, because the two measurements are independent and
// simply adding them would overstate the uncertainty.
//
// When the whole range lies above zero, one node is worse than the other by
// more than chance comfortably explains. That is the test contrast.worse
// applies.
func diffInterval(k1, n1, k2, n2 int) (lo, hi float64) {
	return diffIntervalZ(k1, n1, k2, n2, zScore95)
}

// diffIntervalZ is diffInterval at an arbitrary confidence.
func diffIntervalZ(k1, n1, k2, n2 int, z float64) (lo, hi float64) {
	if n1 == 0 || n2 == 0 {
		return 0, 0
	}
	p1 := float64(k1) / float64(n1)
	p2 := float64(k2) / float64(n2)
	l1, u1 := wilsonZ(k1, n1, z)
	l2, u2 := wilsonZ(k2, n2, z)
	d := p1 - p2
	lo = d - math.Sqrt((p1-l1)*(p1-l1)+(u2-p2)*(u2-p2))
	hi = d + math.Sqrt((u1-p1)*(u1-p1)+(p2-l2)*(p2-l2))
	return lo, hi
}

// tally is one node's exposure and failure count.
//
// Exposure counts packets whose route included the node, not hops through it.
// A packet that met the node on both the forward and the return path counts
// once, because the packet yields a single bit of evidence and must therefore
// contribute a single trial. Counting it twice would weight one observation
// double and would break the independence the binomial assumes, since the two
// hops share one outcome.
type tally struct {
	name     string
	exposure int
	failures int
}

func (t tally) rate() float64 {
	if t.exposure == 0 {
		return 0
	}
	return float64(t.failures) / float64(t.exposure)
}

// tallyNodes counts exposure and failures per node name across observations.
func tallyNodes(obs []observation) map[string]*tally {
	byName := make(map[string]*tally)
	for _, o := range obs {
		seen := make(map[string]struct{}, len(o.forward)+len(o.back))
		for _, hop := range append(append([]string{}, o.forward...), o.back...) {
			if _, dup := seen[hop]; dup {
				continue
			}
			seen[hop] = struct{}{}
			t, ok := byName[hop]
			if !ok {
				t = &tally{name: hop}
				byName[hop] = t
			}
			t.exposure++
			if !o.ok {
				t.failures++
			}
		}
	}
	return byName
}

// group is a set of nodes interchangeable for one position on a route, and
// so comparable against one another.
type group struct {
	label string
	nodes []string
}

// comparisonGroups lists the sets a run may be able to compare within: each
// mix layer, and the gateway and service sets.
//
// The latter two yield a comparison only when the run actually varied them,
// which for the gateway it never does and for the service nodes it does only
// under --rotate-services. Including them regardless costs nothing, since a
// group with fewer than two exposed members produces no contrast, and it
// means the report widens by itself as a run's coverage does.
func comparisonGroups(doc *cpki.Document) []group {
	if doc == nil {
		return nil
	}
	names := func(descs []*cpki.MixDescriptor) []string {
		out := make([]string, 0, len(descs))
		for _, desc := range descs {
			out = append(out, desc.Name)
		}
		sort.Strings(out)
		return out
	}

	groups := make([]group, 0, len(doc.Topology)+2)
	for i, layer := range doc.Topology {
		groups = append(groups, group{fmt.Sprintf("mix layer %d", i+1), names(layer)})
	}
	groups = append(groups,
		group{"gateways", names(doc.GatewayNodes)},
		group{"service nodes", names(doc.ServiceNodes)})
	return groups
}

// report writes the attribution summary. It is deliberately quiet when
// nothing failed: a clean run needs no statistics.
func (a *attribution) report(w io.Writer, doc *cpki.Document) {
	a.mu.Lock()
	obs := append([]observation{}, a.obs...)
	a.mu.Unlock()

	var failures, routed int
	for _, o := range obs {
		if !o.ok {
			failures++
		}
		if len(o.forward) > 0 {
			routed++
		}
	}
	if failures == 0 || len(obs) == 0 {
		return
	}

	fmt.Fprintf(w, "\n%s\n", headerStyle.Render(fmt.Sprintf(
		"Loss attribution: %d packets, %d failures (%.2f%%)",
		len(obs), failures, 100*float64(failures)/float64(len(obs)))))

	if routed == 0 {
		fmt.Fprintf(w, "  no routes reported by the daemon; it likely predates route reporting.\n")
		a.reportOverTime(w, obs)
		return
	}
	if routed < len(obs) {
		fmt.Fprintf(w, "  note: only %d of %d packets carried a route.\n", routed, len(obs))
	}

	fmt.Fprintf(w, "  A failure implicates every hop on its route. These are statistical\n")
	fmt.Fprintf(w, "  associations, not causes: ping can localize loss, never explain it.\n")

	a.reportLayers(w, obs, doc)
	a.reportWindows(w, obs, doc)
	a.reportNotSeparable(w, obs, doc)
	a.reportOverTime(w, obs)
}

// contrast measures one node against the pooled rate of its layer peers.
// This is the quantity a single run can identify: the node drawn from a
// layer varies per packet, while the layer's own contribution to every
// route does not.
type contrast struct {
	node     string
	exposure int
	failures int
	rate     float64
	rateLo   float64
	rateHi   float64
	diff     float64
	diffLo   float64
	diffHi   float64
}

// worse reports whether the node's excess over its peers is distinguishable
// from zero at 95%.
func (c contrast) worse() bool { return c.diffLo > 0 }

// layerContrasts computes each group member against the pooled rest of its
// group. Nodes with no exposure are omitted, and a group with fewer than two
// exposed members yields nothing, there being no peer to compare against.
func layerContrasts(obs []observation, layer []string) []contrast {
	return layerContrastsZ(obs, layer, zScore95)
}

// exclusiveTally counts, for each member of a group, the packets that met
// that member and no other member of the same group.
//
// Counting every packet that merely touched a node does not work. A route
// draws one node from a layer going out and another coming back, so most
// packets that touch a healthy node also touch its faulty neighbour, fail
// because of the neighbour, and are charged to both. Measured on a layer with
// one node dropping 15%, the innocent partner showed 12.4% against the
// culprit's 15.9%: a difference of three points where the truth was fifteen.
//
// Restricting each node's count to packets that met it alone removes the
// confusion entirely, because no other member of the group was in a position
// to drop them. It costs sample size, since a packet whose two draws differ is
// used by neither side, but an undiluted contrast on half the packets beats a
// diluted one on all of them by a wide margin.
func exclusiveTally(obs []observation, group []string) map[string]*tally {
	member := make(map[string]struct{}, len(group))
	for _, name := range group {
		member[name] = struct{}{}
	}

	out := make(map[string]*tally, len(group))
	for _, o := range obs {
		touched := make(map[string]struct{}, 2)
		for _, hop := range append(append([]string{}, o.forward...), o.back...) {
			if _, ok := member[hop]; ok {
				touched[hop] = struct{}{}
			}
		}
		if len(touched) != 1 {
			continue
		}
		for name := range touched {
			t, ok := out[name]
			if !ok {
				t = &tally{name: name}
				out[name] = t
			}
			t.exposure++
			if !o.ok {
				t.failures++
			}
		}
	}
	return out
}

// layerContrastsZ is layerContrasts at an arbitrary confidence.
func layerContrastsZ(obs []observation, layer []string, z float64) []contrast {
	byName := exclusiveTally(obs, layer)
	present := make([]*tally, 0, len(layer))
	for _, name := range layer {
		if t, ok := byName[name]; ok && t.exposure > 0 {
			present = append(present, t)
		}
	}
	if len(present) < 2 {
		return nil
	}

	out := make([]contrast, 0, len(present))
	for _, t := range present {
		restExp, restFail := 0, 0
		for _, other := range present {
			if other != t {
				restExp += other.exposure
				restFail += other.failures
			}
		}
		lo, hi := wilsonZ(t.failures, t.exposure, z)
		dlo, dhi := diffIntervalZ(t.failures, t.exposure, restFail, restExp, z)
		restRate := 0.0
		if restExp > 0 {
			restRate = float64(restFail) / float64(restExp)
		}
		out = append(out, contrast{
			node: t.name, exposure: t.exposure, failures: t.failures,
			rate: t.rate(), rateLo: lo, rateHi: hi,
			diff: t.rate() - restRate, diffLo: dlo, diffHi: dhi,
		})
	}
	return out
}

// reportLayers prints the per-layer contrasts.
func (a *attribution) reportLayers(w io.Writer, obs []observation, doc *cpki.Document) {
	for _, g := range comparisonGroups(doc) {
		cs := layerContrasts(obs, g.nodes)
		if len(cs) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  %s\n", g.label)
		fmt.Fprintf(w, "    %-22s %8s %6s %20s  %s\n",
			"node", "packets", "fail", "rate [95% CI]", "vs rest of layer")
		for _, c := range cs {
			flag := ""
			if c.worse() {
				flag = "  <-- worse than its peers"
			}
			fmt.Fprintf(w, "    %-22s %8d %6d  %6.2f%% [%4.2f-%4.2f]  %+6.2f%% [%+.2f, %+.2f]%s\n",
				c.node, c.exposure, c.failures, 100*c.rate, 100*c.rateLo, 100*c.rateHi,
				100*c.diff, 100*c.diffLo, 100*c.diffHi, flag)
		}
	}
}

// zForTests returns the z to use when m separate comparisons are made, so
// that the chance of any one of them misfiring stays near 5% rather than 5%
// each. With twenty windows and six nodes there are a hundred and twenty
// opportunities for chance to produce something striking, and at a plain 95%
// roughly six of them would.
//
// The correction is Bonferroni's: test each comparison at 5%/m instead of 5%.
// It is the blunt instrument of its family and errs toward missing things
// rather than inventing them, which is the right way round for a tool whose
// output an operator may act on.
func zForTests(m int) float64 {
	if m < 1 {
		m = 1
	}
	alpha := 0.05 / float64(m)
	return math.Sqrt2 * math.Erfinv(1-alpha)
}

// scanWindowCount picks how finely to slice a run.
//
// The choice is a trade. Wider windows hold more packets and so can resolve a
// smaller difference, but they average a short episode away, which is the very
// thing the scan exists to catch. Narrower windows do the reverse, and also
// multiply the comparisons, which zForTests then charges for.
//
// Measured against simulation on a 3000-packet run: a culprit that swaps
// halfway is caught every time between four and ten windows and starts to slip
// by twenty, while a node bad for a thirtieth of the run is caught about half
// the time and improves with more windows. Around 250 packets per window
// serves both, so that is what this aims for, bounded so that a short run is
// not sliced into noise nor a long one into hundreds of comparisons.
func scanWindowCount(packets int) int {
	n := packets / 250
	if n < 4 {
		n = 4
	}
	if n > 16 {
		n = 16
	}
	return n
}

// windowFinding is a node that stood out from its peers during one stretch of
// the run.
type windowFinding struct {
	group string
	start time.Time
	end   time.Time
	c     contrast
}

// bucketize splits observations into n consecutive windows of equal duration.
// Windows with no traffic come back empty rather than being dropped, so a
// caller can still report when they were.
func bucketize(obs []observation, n int) ([][]observation, time.Time, time.Duration) {
	timed := make([]observation, 0, len(obs))
	for _, o := range obs {
		if !o.at.IsZero() {
			timed = append(timed, o)
		}
	}
	if len(timed) < 2 || n < 1 {
		return nil, time.Time{}, 0
	}
	sort.Slice(timed, func(i, j int) bool { return timed[i].at.Before(timed[j].at) })
	start := timed[0].at
	span := timed[len(timed)-1].at.Sub(start)
	if span <= 0 {
		return nil, time.Time{}, 0
	}
	width := span / time.Duration(n)
	if width <= 0 {
		return nil, time.Time{}, 0
	}

	out := make([][]observation, n)
	for _, o := range timed {
		i := int(o.at.Sub(start) / width)
		if i >= n {
			i = n - 1
		}
		out[i] = append(out[i], o)
	}
	return out, start, width
}

// scanWindows looks for a node that was worse than its peers during part of
// the run.
//
// A whole-run comparison answers "was this node worse on average", which is
// the wrong question when loss arrives in episodes. Averaged over a long
// batch, a node that failed badly for two minutes looks nearly innocent, and
// two nodes that each failed badly at different times look identical to each
// other and so to the comparison, which then reports nothing at all. Measured
// against simulation, the whole-run comparison misses a swapping culprit
// entirely and catches a node that is bad for a thirtieth of the run less than
// one time in ten.
//
// Scanning windows restores both cases, at the cost of many more comparisons,
// which zForTests pays for.
func scanWindows(obs []observation, groups []group, windows int) []windowFinding {
	buckets, start, width := bucketize(obs, windows)
	if buckets == nil {
		return nil
	}

	comparisons := 0
	for _, b := range buckets {
		for _, g := range groups {
			comparisons += len(layerContrasts(b, g.nodes))
		}
	}
	z := zForTests(comparisons)

	found := make([]windowFinding, 0, 4)
	for i, b := range buckets {
		for _, g := range groups {
			for _, c := range layerContrastsZ(b, g.nodes, z) {
				if c.diffLo > 0 {
					found = append(found, windowFinding{
						group: g.label,
						start: start.Add(time.Duration(i) * width),
						end:   start.Add(time.Duration(i+1) * width),
						c:     c,
					})
				}
			}
		}
	}
	return found
}

// reportWindows prints anything the windowed scan turned up, and says plainly
// when it turned up nothing, since silence here is a weaker statement than it
// looks.
func (a *attribution) reportWindows(w io.Writer, obs []observation, doc *cpki.Document) {
	groups := comparisonGroups(doc)
	if len(groups) == 0 {
		return
	}
	found := scanWindows(obs, groups, scanWindowCount(len(obs)))
	if len(found) == 0 {
		fmt.Fprintf(w, "\n  no node stood out within any single window either.\n")
		return
	}

	fmt.Fprintf(w, "\n  worse than its peers during part of the run:\n")
	for _, f := range found {
		fmt.Fprintf(w, "    %s-%s  %-16s %-22s %d/%d failed  %+.1f%% vs peers\n",
			f.start.Format("15:04:05"), f.end.Format("15:04:05"), f.group,
			f.c.node, f.c.failures, f.c.exposure, 100*f.c.diff)
	}
	fmt.Fprintf(w, "  Loss that comes and goes is averaged away by the whole-run\n")
	fmt.Fprintf(w, "  comparison above, so a node named here and not there is not a\n")
	fmt.Fprintf(w, "  contradiction: it was bad for a while rather than throughout.\n")
}

// reportNotSeparable names the nodes whose contribution cannot be told apart
// from the run's baseline, so that a reader does not mistake their absence
// from the tables above for a clean bill of health.
func (a *attribution) reportNotSeparable(w io.Writer, obs []observation, doc *cpki.Document) {
	byName := tallyNodes(obs)
	constant := make([]string, 0, 4)
	for name, t := range byName {
		if t.exposure == len(obs) {
			constant = append(constant, name)
		}
	}
	if len(constant) == 0 {
		return
	}
	sort.Strings(constant)
	fmt.Fprintf(w, "\n  on every route, so not separable from the baseline: %s\n",
		strings.Join(constant, ", "))
	fmt.Fprintf(w, "  Each layer's common level is confounded with them too; only\n")
	fmt.Fprintf(w, "  within-layer differences and the overall rate are identified.\n")
}

// reportOverTime buckets failures across the run. Loss is often episodic:
// averaging a burst over a long batch reports a small number everywhere and
// describes neither the burst nor the quiet.
func (a *attribution) reportOverTime(w io.Writer, obs []observation) {
	timed := make([]observation, 0, len(obs))
	for _, o := range obs {
		if !o.at.IsZero() {
			timed = append(timed, o)
		}
	}
	if len(timed) < 2 {
		return
	}
	sort.Slice(timed, func(i, j int) bool { return timed[i].at.Before(timed[j].at) })
	span := timed[len(timed)-1].at.Sub(timed[0].at)
	if span <= 0 {
		return
	}

	const buckets = 20
	width := span / buckets
	if width <= 0 {
		return
	}
	sent := make([]int, buckets)
	lost := make([]int, buckets)
	start := timed[0].at
	for _, o := range timed {
		b := int(o.at.Sub(start) / width)
		if b >= buckets {
			b = buckets - 1
		}
		sent[b]++
		if !o.ok {
			lost[b]++
		}
	}

	fmt.Fprintf(w, "\n  failures over time (%s buckets, run spans %s)\n",
		width.Round(time.Second), span.Round(time.Second))
	for i := 0; i < buckets; i++ {
		if sent[i] == 0 {
			continue
		}
		frac := float64(lost[i]) / float64(sent[i])
		bar := strings.Repeat("#", int(frac*40+0.5))
		fmt.Fprintf(w, "    %8s  %4d sent %4d lost  %5.1f%% %s\n",
			start.Add(time.Duration(i)*width).Format("15:04:05"),
			sent[i], lost[i], 100*frac, bar)
	}
}
