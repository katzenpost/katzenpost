// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type memStore struct {
	mu    sync.Mutex
	boxes map[uint64][]byte
}

func (m *memStore) write(k uint64, b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.boxes == nil {
		m.boxes = map[uint64][]byte{}
	}
	if _, ok := m.boxes[k]; ok {
		return errors.New("box rewritten")
	}
	m.boxes[k] = append([]byte{}, b...)
	return nil
}

func (m *memStore) next(start uint64) func() ([]byte, error) {
	k := start
	return func() ([]byte, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		b, ok := m.boxes[k]
		if !ok {
			return nil, errors.New("missing box")
		}
		k++
		return b, nil
	}
}

func testStream(audioPages int) (stream []byte, init []byte, starts []int) {
	r := rand.New(rand.NewSource(1))
	pages := [][]byte{oggPage('h', 19), oggPage('t', 40)}
	for i := 0; i < audioPages; i++ {
		lacing := make([]byte, 1+r.Intn(4))
		for j := range lacing {
			lacing[j] = byte(1 + r.Intn(120))
		}
		pages = append(pages, oggPage(byte(i), lacing...))
	}
	for i, p := range pages {
		if i == 2 {
			init = append([]byte{}, stream...)
		}
		starts = append(starts, len(stream))
		stream = append(stream, p...)
	}
	return stream, init, starts[2:]
}

func TestSendPlayFromStart(t *testing.T) {
	stream, init, _ := testStream(60)
	var m memStore
	published := 0
	require.NoError(t, send(bytes.NewReader(stream), 400, 3, m.write, func() {
		require.Contains(t, m.boxes, uint64(0))
		published++
	}))
	require.Equal(t, 1, published)
	h, err := unmarshalFrame(m.boxes[0])
	require.NoError(t, err)
	require.Equal(t, kindHeader, h.kind)
	codec, gotInit, err := parseHeaderBody(h.body)
	require.NoError(t, err)
	require.Equal(t, codecOpus, codec)
	require.Equal(t, init, gotInit)
	last := uint64(len(m.boxes) - 1)
	end, err := unmarshalFrame(m.boxes[last])
	require.NoError(t, err)
	require.Equal(t, kindEnd, end.kind)
	for k := uint64(1); k < last; k++ {
		require.LessOrEqual(t, len(m.boxes[k]), 400)
	}
	var out bytes.Buffer
	require.NoError(t, play(&out, gotInit, m.next(1)))
	require.Equal(t, stream, out.Bytes())
}

func TestPlayJoin(t *testing.T) {
	stream, init, starts := testStream(60)
	var m memStore
	require.NoError(t, send(bytes.NewReader(stream), 400, 1, m.write, func() {}))
	joined := 0
	for k := uint64(1); k < uint64(len(m.boxes)-1); k++ {
		boxStart := len(init) + int(k-1)*(400-frameOverhead)
		want := len(stream)
		for _, s := range starts {
			if s >= boxStart {
				want = s
				break
			}
		}
		var out bytes.Buffer
		require.NoError(t, play(&out, init, m.next(k)))
		require.Equal(t, append(append([]byte{}, init...), stream[want:]...), out.Bytes(), k)
		if want < len(stream) {
			joined++
		}
	}
	require.Greater(t, joined, 10)
}

func TestPlayRejectsHeaderMidStream(t *testing.T) {
	var m memStore
	require.NoError(t, m.write(1, frame{kind: kindHeader, sync: noSync}.marshal()))
	require.Error(t, play(&bytes.Buffer{}, nil, m.next(1)))
}

func TestSendRefusesOversizedHeader(t *testing.T) {
	in := append(oggPage('h', 19), oggPage('t', 255, 255, 10)...)
	var m memStore
	err := send(bytes.NewReader(in), 256, 1, m.write, func() { t.Fatal("published") })
	require.Error(t, err)
	require.Empty(t, m.boxes)
}

func TestSendStopsOnWriteError(t *testing.T) {
	stream, _, _ := testStream(60)
	boom := errors.New("boom")
	var calls atomic.Int64
	err := send(bytes.NewReader(stream), 400, 2, func(k uint64, b []byte) error {
		calls.Add(1)
		if k == 3 {
			return boom
		}
		time.Sleep(5 * time.Millisecond)
		return nil
	}, func() {})
	require.ErrorIs(t, err, boom)
	require.Less(t, calls.Load(), int64(10))
}

func TestOrdered(t *testing.T) {
	const window = 3
	var inFlight, peak atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	next := ordered(ctx, window, 5, time.Minute, func(ctx context.Context, k uint64) ([]byte, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(time.Duration(rand.Intn(3)) * time.Millisecond)
		return []byte{byte(k)}, nil
	})
	for k := 5; k < 60; k++ {
		b, err := next()
		require.NoError(t, err)
		require.Equal(t, []byte{byte(k)}, b)
	}
	cancel()
	require.LessOrEqual(t, peak.Load(), int64(window+1))
	require.Greater(t, peak.Load(), int64(1))
}

func TestOrderedCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	next := ordered(ctx, 2, 1, time.Minute, func(ctx context.Context, k uint64) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	cancel()
	_, err := next()
	require.ErrorIs(t, err, context.Canceled)
}

func TestOrderedStall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	next := ordered(ctx, 2, 1, 50*time.Millisecond, func(ctx context.Context, k uint64) ([]byte, error) {
		if k == 3 {
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
			}
		}
		return []byte{byte(k)}, nil
	})
	for k := 1; k < 3; k++ {
		b, err := next()
		require.NoError(t, err)
		require.Equal(t, []byte{byte(k)}, b)
	}
	_, err := next()
	require.ErrorIs(t, err, errStalled)
	require.EqualError(t, err, "no new audio for 50ms: the broadcaster has gone off the air")
}

func TestSendEndsStreamOnBadInput(t *testing.T) {
	stream, _, starts := testStream(20)
	cut := starts[len(starts)-1] + 5
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"truncated": {stream[:cut], io.ErrUnexpectedEOF},
		"garbage":   {append(stream[:starts[len(starts)-1]:starts[len(starts)-1]], []byte("not an ogg page, not at all.")...), errNotOgg},
	} {
		var m memStore
		err := send(bytes.NewReader(tc.in), 400, 2, m.write, func() {})
		require.ErrorIs(t, err, tc.want, name)
		end, err := unmarshalFrame(m.boxes[uint64(len(m.boxes)-1)])
		require.NoError(t, err, name)
		require.Equal(t, kindEnd, end.kind, name)
		h, err := unmarshalFrame(m.boxes[0])
		require.NoError(t, err, name)
		_, init, err := parseHeaderBody(h.body)
		require.NoError(t, err, name)
		var out bytes.Buffer
		require.NoError(t, play(&out, init, m.next(1)), name)
		require.Equal(t, stream[:starts[len(starts)-1]], out.Bytes(), name)
	}
}

func TestStoppable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("abc"))
		time.Sleep(2 * time.Second)
		pw.Write([]byte("late"))
		pw.Close()
	}()
	r := stoppable(ctx, pr)
	head := make([]byte, 3)
	_, err := io.ReadFull(r, head)
	require.NoError(t, err)
	require.Equal(t, []byte("abc"), head)
	cancel()
	rest, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Empty(t, rest)
}
