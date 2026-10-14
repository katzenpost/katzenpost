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
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/common"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/cmd/internal/mixclient"
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

// sendPing sends one ping and reports the outcome together with the route the
// daemon chose for it. The route is recorded on failure as well as success,
// which is the whole point: a packet that never came back is the one whose
// hops we most want to know.
func sendPing(session *thin.ThinClient, service string, serviceDesc *common.ServiceDescriptor, timeout, slop time.Duration, printDiff bool) observation {
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
	res, err := session.BlockingSendMessageWithResult(ctx, cborPayload, &id, serviceDesc.RecipientQueueID, slop)

	// A result accompanies a failed send whenever the packet actually went
	// out, so build the observation from it either way.
	o := observation{at: time.Now()}
	sent := res != nil && !res.SentAt.IsZero()
	if res != nil {
		o.forward = res.ForwardRoute
		o.back = res.ReturnRoute
		if !res.SentAt.IsZero() {
			o.at = res.SentAt
		}
	}

	if err != nil {
		fmt.Printf("\nerror: %v\n", err)
		o.cat = classify(sent, false, err)
		return o
	}

	payloadOK, replyPayload := replyDelivered(service, res.Payload, pingPayload)
	if service != echoService {
		fmt.Printf("\n%s replied: %q\n", service, replyPayload)
	}
	if !payloadOK && printDiff {
		fmt.Printf("\nReply payload: %x\nOriginal payload: %x\n", replyPayload, pingPayload)
	}
	o.cat = classify(sent, payloadOK, nil)
	o.ok = o.cat == catDelivered
	return o
}

const echoService = "echo"

func replyDelivered(service string, reply, sent []byte) (bool, []byte) {
	if service != echoService {
		text, _ := cpki.PrintableMOTD(reply, cpki.MaxMOTDLength)
		return true, text
	}
	var got []byte
	if _, err := cbor.UnmarshalFirst(reply, &got); err != nil {
		return false, reply
	}
	return bytes.Equal(got, sent), got
}

// sendPings sends count pings and returns the per-category outcome counts.
// Callers decide from these which categories gate a non-zero exit, so the
// ping can be used as a smoke-test that fails only on genuine mixnet loss.
func sendPings(session *thin.ThinClient, service string, services []*common.ServiceDescriptor, count int, concurrency int, printDiff bool) counts {
	// Extract service name from RecipientQueueID (remove leading '+' if present)
	serviceName := string(services[0].RecipientQueueID)
	nodeName := services[0].MixDescriptor.Name
	if len(services) > 1 {
		names := make([]string, 0, len(services))
		for _, s := range services {
			names = append(names, s.MixDescriptor.Name)
		}
		nodeName = "{" + strings.Join(names, ",") + "}"
	}

	// Derive the per-packet timeout from the consensus parameters
	// rather than asking the operator. See roundTripTimeout for the
	// derivation. The value is computed once per batch so all pings
	// in this invocation see the same ceiling, even though the PKI
	// document may rotate during a long batch; in practice Mu and the
	// topology change rarely enough that recomputing per ping would
	// add complexity without benefit.
	timeout := mixclient.RoundTripTimeout(session.PKIDocument())
	slop := mixclient.ReplySlop(session.PKIDocument())

	fmt.Println("Control-C to abort...")
	fmt.Printf("%s\n", headerStyle.Render(fmt.Sprintf(
		"Sending %d Sphinx packets to %s@%s (reply due + %s, hard cap %s)",
		count, serviceName, nodeName, slop, timeout)))

	var tally counts
	attrib := new(attribution)

	wg := new(sync.WaitGroup)
	sem := make(chan struct{}, concurrency)

	for i := 0; i < count; i++ {

		sem <- struct{}{}

		wg.Add(1)

		// Rotate across the available services so the destination varies;
		// with a single service this is the previous fixed behaviour.
		desc := services[i%len(services)]

		// make new goroutine for each ping to send them in parallel
		go func() {
			o := sendPing(session, service, desc, timeout, slop, printDiff)
			attrib.record(o)
			atomic.AddUint64(&tally[o.cat], 1)
			if o.ok {
				fmt.Printf("%s", successStyle.Render("!"))
			} else {
				fmt.Printf("%s", failureStyle.Render("~"))
			}
			wg.Done()
			<-sem
		}()
	}

	wg.Wait()
	fmt.Printf("\n")

	passed := tally[catDelivered]
	percent := (float64(passed) * float64(100)) / float64(count)
	successMsg := fmt.Sprintf("Success rate is %.0f percent (%d/%d)", percent, passed, count)
	if percent >= 90.0 {
		fmt.Printf("%s\n", successStyle.Render(successMsg))
	} else if percent >= 50.0 {
		fmt.Printf("%s\n", infoStyle.Render(successMsg))
	} else {
		fmt.Printf("%s\n", failureStyle.Render(successMsg))
	}

	reportCategories(os.Stdout, tally)
	attrib.reportEpochs(os.Stdout)
	attrib.report(os.Stdout, session.PKIDocument())

	return tally
}

func reportCategories(w io.Writer, tally counts) {
	fmt.Fprintf(w, "%s\n", headerStyle.Render("Outcomes by category:"))
	fmt.Fprintf(w, "  %-10s %6d  reply received within budget\n", catDelivered.label(), tally[catDelivered])
	fmt.Fprintf(w, "  %-10s %6d  dispatched, no reply before the hard cap\n", catLost.label(), tally[catLost])
	fmt.Fprintf(w, "  %-10s %6d  dispatched, no reply before the daemon dropped the SURB\n", catOverdue.label(), tally[catOverdue])
	fmt.Fprintf(w, "  %-10s %6d  never dispatched (client pacing/limit), not a mixnet loss\n", catNotSent.label(), tally[catNotSent])
	fmt.Fprintf(w, "  %-10s %6d  client daemon link went down, outcome unknown\n", catRefused.label(), tally[catRefused])
	fmt.Fprintf(w, "  gate: %s + %s (--strict: everything but %s)\n", catLost.label(), catOverdue.label(), catDelivered.label())
}
