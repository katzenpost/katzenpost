// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestTooEarlyCoversEveryStatus(t *testing.T) {
	for _, tc := range []struct {
		resp commands.Command
		want bool
	}{
		{&commands.CertStatus{ErrorCode: commands.CertTooEarly}, true},
		{&commands.CertStatus{ErrorCode: commands.CertOk}, false},
		{&commands.CertStatus{ErrorCode: commands.CertTooLate}, false},
		{&commands.VoteStatus{ErrorCode: commands.VoteTooEarly}, true},
		{&commands.VoteStatus{ErrorCode: commands.VoteOk}, false},
		{&commands.VoteStatus{ErrorCode: commands.VoteTooLate}, false},
		{&commands.RevealStatus{ErrorCode: commands.RevealTooEarly}, true},
		{&commands.RevealStatus{ErrorCode: commands.RevealOk}, false},
		{&commands.RevealStatus{ErrorCode: commands.RevealTooLate}, false},
		{&commands.SigStatus{ErrorCode: commands.SigTooEarly}, true},
		{&commands.SigStatus{ErrorCode: commands.SigOk}, false},
		{&commands.SigStatus{ErrorCode: commands.SigTooLate}, false},
		{&commands.Consensus{}, false},
		{nil, false},
	} {
		require.Equal(t, tc.want, tooEarly(tc.resp), "%T %+v", tc.resp, tc.resp)
	}
}

func TestSendToPeerUntilHonoursMaxAttempts(t *testing.T) {
	sender := retryTestSender(t)
	var dials int32
	sender.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, errors.New("connection refused")
	}
	start := time.Now()
	_, err := sender.sendCommandToPeerUntil(retryTestPeer(), retryTestCert(sender), start.Add(10*time.Second), 2)
	require.Error(t, err)
	require.Equal(t, int32(3), atomic.LoadInt32(&dials))
	require.Less(t, time.Since(start), 5*time.Second)
}
