//go:build latency_bench && docker_test

// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

// BenchmarkPigeonholeWrite measures end-to-end latency for one
// pigeonhole write (courier acceptance / replica reply), with no
// artificial delays. Requires a running docker mixnet.
//
// Build tags: latency_bench && docker_test. Both are required so the
// benchmark stays out of CI (which sets only docker_test) and is run
// only by hand. Invoke as:
//
//	go test -tags='docker_test latency_bench' \
//	    -bench=BenchmarkPigeonholeWrite -count=1 -run=^$ \
//	    -benchtime=20x ./client/
//
// Reports b.N's median and p95 in milliseconds via b.ReportMetric so
// pre-change and post-change runs may be compared directly.
//
// The existing pigeonhole integration tests are unsuitable for this
// purpose: they include a 30-second sleep between write and read to
// bridge the write→replication→read race
// (client/pigeonhole_docker_test.go:101). A latency benchmark cannot
// tolerate that.
func BenchmarkPigeonholeWrite(b *testing.B) {
	client := setupThinClient(b)
	defer client.Close()

	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(b, err)

	writeCap, _, msgIdx, err := client.NewKeypair(seed)
	require.NoError(b, err)
	require.NotNil(b, writeCap)
	require.NotNil(b, msgIdx)

	// Sized over 29 bytes so the courier returns ReplyTypePayload rather
	// than ReplyTypeAck. See pigeonhole_docker_test.go:74 for the
	// rationale.
	payload := []byte(
		"benchmark payload, sized over twenty-nine bytes to elicit ReplyTypePayload from the courier",
	)

	durations := make([]time.Duration, 0, b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ciphertext, envDesc, envHash, nextIdx, err :=
			client.EncryptWrite(payload, writeCap, msgIdx)
		require.NoError(b, err)
		replyIdx := uint8(0)
		b.StartTimer()

		start := time.Now()
		_, err = client.StartResendingEncryptedMessage(
			nil, writeCap, nil, &replyIdx, envDesc, ciphertext, envHash,
		)
		elapsed := time.Since(start)

		require.NoError(b, err)

		b.StopTimer()
		durations = append(durations, elapsed)
		msgIdx = nextIdx
		b.StartTimer()
	}
	b.StopTimer()

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	median := durations[len(durations)/2]
	p95 := durations[(len(durations)*95)/100]
	if p95 >= time.Duration(len(durations)) {
		p95 = durations[len(durations)-1]
	}
	b.ReportMetric(float64(median.Milliseconds()), "median_ms")
	b.ReportMetric(float64(p95.Milliseconds()), "p95_ms")
}
