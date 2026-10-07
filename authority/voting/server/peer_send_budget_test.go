// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestPeerSendsEndAtTheirPhaseDeadline(t *testing.T) {
	for _, c := range []struct {
		name string
		code uint8
		send func(s *state)
		want time.Duration
	}{
		{"vote", commands.VoteOk, func(s *state) { s.sendVoteToAuthorities([]byte("v"), 1) }, AuthorityVoteDeadline()},
		{"reveal", commands.RevealOk, func(s *state) { s.sendRevealToAuthorities([]byte("r"), 1) }, AuthorityRevealDeadline()},
		{"cert", commands.CertOk, func(s *state) { s.sendCertToAuthorities([]byte("c"), 1) }, AuthorityCertDeadline()},
		{"sig", commands.SigOk, func(s *state) { s.sendSigToAuthorities([]byte("s"), 1) }, PublishConsensusDeadline()},
	} {
		t.Run(c.name, func(t *testing.T) {
			sender, _ := clockLogSender(t, c.code)
			var mu sync.Mutex
			var targets []time.Duration
			sender.phaseDeadlineFn = func(target time.Duration) time.Time {
				mu.Lock()
				targets = append(targets, target)
				mu.Unlock()
				return time.Now().Add(600 * time.Millisecond)
			}
			sender.Lock()
			c.send(sender)
			sender.Unlock()
			mu.Lock()
			defer mu.Unlock()
			require.Equal(t, []time.Duration{c.want}, targets)
		})
	}
	require.Equal(t, []time.Duration{2, 3, 4, 5}, []time.Duration{
		AuthorityVoteDeadline() / MixPublishDeadline(),
		AuthorityRevealDeadline() / MixPublishDeadline(),
		AuthorityCertDeadline() / MixPublishDeadline(),
		PublishConsensusDeadline() / MixPublishDeadline(),
	})
}
