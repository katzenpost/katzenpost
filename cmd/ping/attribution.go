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
// The textbook interval, p ± z·sqrt(p(1-p)/n), is unusable here. With zero
// failures it collapses to [0, 0], claiming certainty from an absence of
// evidence, and its coverage falls well below the nominal level whenever n is
// small or the rate is near zero, which is our ordinary case.
//
// Wilson inverts the score test instead. Rather than placing an interval
// around the observed rate, it asks which true rates would leave the observed
// count unsurprising, solving
//
//	|p̂ - p| / sqrt(p(1-p)/n) <= z
//
// for p. That is a quadratic in p, and its two roots are the bounds; the
// closed form below is that solution rearranged. The (1 + z²/n) denominator is
// not a fudge factor but falls out of the algebra, and it is what pulls the
// estimate slightly toward one half, so that zero failures still yields a
// positive upper bound: 0 in 100 gives [0, 3.70%], which is the honest reading
// of no failures yet.
func wilson(k, n int) (lo, hi float64) {
	if n == 0 {
		return 0, 0
	}
	p := float64(k) / float64(n)
	z := zScore95
	nf := float64(n)
	denom := 1 + z*z/nf
	center := (p + z*z/(2*nf)) / denom
	half := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf)) / denom
	return math.Max(0, center-half), math.Min(1, center+half)
}

// diffInterval returns a 95% interval for p1-p2 by Newcombe's score method.
//
// Adding the two variances and appealing to normality fails for the same
// reason the textbook interval does: when either count is zero its variance
// term vanishes and the interval is far too narrow. Newcombe composes the two
// Wilson intervals instead. The difference is at its most negative when p1
// sits at its own lower plausible bound and p2 at its upper, so those two
// distances bound the excursion; they are combined in quadrature rather than
// added because the two estimates are independent, and adding them would be
// needlessly conservative.
//
// An interval lying wholly above zero is what licenses the claim that one node
// is worse than its peers. See contrast.worse.
func diffInterval(k1, n1, k2, n2 int) (lo, hi float64) {
	if n1 == 0 || n2 == 0 {
		return 0, 0
	}
	p1 := float64(k1) / float64(n1)
	p2 := float64(k2) / float64(n2)
	l1, u1 := wilson(k1, n1)
	l2, u2 := wilson(k2, n2)
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
	byName := tallyNodes(obs)
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
		lo, hi := wilson(t.failures, t.exposure)
		dlo, dhi := diffInterval(t.failures, t.exposure, restFail, restExp)
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
