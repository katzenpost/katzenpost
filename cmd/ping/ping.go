// ping.go - Katzenpost ping tool
// Copyright (C) 2021  David Stainton
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

package main

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/common"
	"github.com/katzenpost/katzenpost/client/thin"
	kpcommon "github.com/katzenpost/katzenpost/common"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

var basePayload = []byte(`Data encryption is used widely to protect the content of Internet
communications and enables the myriad of activities that are popular today,
from online banking to chatting with loved ones. However, encryption is not
sufficient to protect the meta-data associated with the communications.

Modern encrypted communication networks are vulnerable to traffic analysis and
can leak such meta-data as the social graph of users, their geographical
location, the timing of messages and their order, message size, and many other
kinds of meta-data.

Since 1979, there has been active academic research into communication
meta-data protection, also called anonymous communication networking, that has
produced various designs. Of these, mix networks are among the most practical
and can readily scale to millions of users.
`)

// Color styles for ping output
var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true) // Bright green
	failureStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)  // Bright red
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true) // Bright cyan
	headerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true) // Bright yellow
)

// perHopSlopMs is the wall-clock budget per Sphinx hop on top of the
// encoded per-hop delay. It covers crypto unwrap, scheduler dwell, and
// network transmission between adjacent nodes. 500ms is comfortably
// above the server's default SchedulerSlack (450ms) plus typical
// crypto/network overhead, and the budget multiplies by the hop count
// so a longer topology gets proportionally more slack.
const perHopSlopMs uint64 = 500

// fallbackRoundTrip is the timeout used when the PKI document is not
// yet available. It is well above any honest path's RTT and well below
// the one-epoch SURB validity window, so the ping cannot block
// indefinitely waiting for a doc.
const fallbackRoundTrip = 60 * time.Second

// roundTripTimeout returns the per-packet timeout derived from the
// consensus document's Mu parameter and topology. Per-hop delays are
// drawn from Exp(Mu) and clamped at common.SafetyCap(Mu) (the
// 1 - 10^-12 quantile), so the encoded Sphinx round-trip delay is
// strictly bounded above by hops × SafetyCap(Mu). We add a per-hop
// slop budget for processing and network overhead. The result is a
// timeout that effectively never false-positives on an honest path
// and which cuts off lost packets in tens of seconds rather than
// blocking the batch forever.
//
// The hop count for an echo round-trip is 2L + 3 where L is the
// number of mix layers: forward path is gateway + L mixes + service
// (L + 2 hops with encoded delays because the packet carries a SURB),
// SURB return is L mixes + gateway (L + 1 hops). For the default
// L = 3 topology this is 9, matching the paper's Erlang-9 analysis.
func roundTripTimeout(doc *cpki.Document) time.Duration {
	if doc == nil || doc.Mu <= 0 || len(doc.Topology) == 0 {
		return fallbackRoundTrip
	}
	hops := uint64(2*len(doc.Topology) + 3)
	perHopCapMs := kpcommon.SafetyCap(doc.Mu)
	if perHopCapMs == 0 {
		return fallbackRoundTrip
	}
	totalMs := hops * (perHopCapMs + perHopSlopMs)
	return time.Duration(totalMs) * time.Millisecond
}

func sendPing(session *thin.ThinClient, serviceDesc *common.ServiceDescriptor, timeout time.Duration, printDiff bool) bool {
	var nonce [32]byte

	_, err := rand.Reader.Read(nonce[:])

	if err != nil {
		panic(err)
	}

	pingPayload := append(nonce[:], basePayload...)

	cborPayload, err := cbor.Marshal(pingPayload)
	if err != nil {
		fmt.Printf("Failed to marshal: %v\n", err)
		panic(err)
	}

	id := hash.Sum256(serviceDesc.MixDescriptor.IdentityKey)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	reply, err := session.BlockingSendMessage(ctx, cborPayload, &id, serviceDesc.RecipientQueueID)
	if err != nil {
		fmt.Printf("\nerror: %v\n", err)
		fmt.Printf("%s", failureStyle.Render(".")) // Fail, did not receive a reply.
		return false
	}

	var replyPayload []byte

	_, err = cbor.UnmarshalFirst(reply, &replyPayload)
	if err != nil {
		fmt.Printf("Failed to unmarshal: %s\n", err)
		panic(err)
	}

	if bytes.Equal(replyPayload, pingPayload) {
		// OK, received identical payload in reply.hash.Sum256(serviceDesc.MixDescriptor.IdentityKey)
		return true
	} else {
		// Fail, received unexpected payload in reply.

		if printDiff {
			fmt.Printf("\nReply payload: %x\nOriginal payload: %x\n", replyPayload, pingPayload)
		}
		return false
	}
}

func sendPings(session *thin.ThinClient, serviceDesc *common.ServiceDescriptor, count int, concurrency int, printDiff bool) {
	// Extract service name from RecipientQueueID (remove leading '+' if present)
	serviceName := string(serviceDesc.RecipientQueueID)
	nodeName := serviceDesc.MixDescriptor.Name

	// Derive the per-packet timeout from the consensus parameters
	// rather than asking the operator. See roundTripTimeout for the
	// derivation. The value is computed once per batch so all pings
	// in this invocation see the same ceiling, even though the PKI
	// document may rotate during a long batch; in practice Mu and the
	// topology change rarely enough that recomputing per ping would
	// add complexity without benefit.
	timeout := roundTripTimeout(session.PKIDocument())

	fmt.Println("Control-C to abort...")
	fmt.Printf("%s\n", headerStyle.Render(fmt.Sprintf("Sending %d Sphinx packets to %s@%s (per-packet timeout %s)", count, serviceName, nodeName, timeout)))

	var passed, failed uint64

	wg := new(sync.WaitGroup)
	sem := make(chan struct{}, concurrency)

	for i := 0; i < count; i++ {

		sem <- struct{}{}

		wg.Add(1)

		// make new goroutine for each ping to send them in parallel
		go func() {
			if sendPing(session, serviceDesc, timeout, printDiff) {
				fmt.Printf("%s", successStyle.Render("!"))
				atomic.AddUint64(&passed, 1)
			} else {
				fmt.Printf("%s", failureStyle.Render("~"))
				atomic.AddUint64(&failed, 1)
			}
			wg.Done()
			<-sem
		}()
	}

	wg.Wait()
	fmt.Printf("\n")

	percent := (float64(passed) * float64(100)) / float64(count)
	successMsg := fmt.Sprintf("Success rate is %.0f percent (%d/%d)", percent, passed, count)
	if percent >= 90.0 {
		fmt.Printf("%s\n", successStyle.Render(successMsg))
	} else if percent >= 50.0 {
		fmt.Printf("%s\n", infoStyle.Render(successMsg))
	} else {
		fmt.Printf("%s\n", failureStyle.Render(successMsg))
	}
}
